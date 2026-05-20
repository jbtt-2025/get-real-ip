package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RadixNode 基数树节点
type RadixNode struct {
	children [2]*RadixNode
	isPrefix bool
}

// IPPrefixTrie 区分 v4/v6 的高性能前缀树
type IPPrefixTrie struct {
	v4Root RadixNode
	v6Root RadixNode
}

func (t *IPPrefixTrie) Insert(prefix netip.Prefix) {
	addr := prefix.Addr().Unmap()
	bits := prefix.Bits()
	var current *RadixNode
	var ipBytes []byte

	if addr.Is4() {
		current = &t.v4Root
		v4 := addr.As4()
		ipBytes = v4[:]
	} else {
		current = &t.v6Root
		v6 := addr.As6()
		ipBytes = v6[:]
	}

	for i := 0; i < bits; i++ {
		bit := (ipBytes[i>>3] >> (7 - (i & 7))) & 1
		if current.children[bit] == nil {
			current.children[bit] = &RadixNode{}
		}
		current = current.children[bit]

		if current.isPrefix {
			return
		}
	}
	current.isPrefix = true
}

func (t *IPPrefixTrie) Contains(ip netip.Addr) bool {
	var current *RadixNode
	var ipBytes []byte

	if ip.Is4() {
		current = &t.v4Root
		v4 := ip.As4()
		ipBytes = v4[:]
	} else {
		current = &t.v6Root
		v6 := ip.As6()
		ipBytes = v6[:]
	}

	totalBits := len(ipBytes) * 8
	for i := 0; i < totalBits; i++ {
		// 前置判断，完美修复 /0 边界，并实现子网段提早命中截断
		if current.isPrefix {
			return true
		}
		
		bit := (ipBytes[i>>3] >> (7 - (i & 7))) & 1
		current = current.children[bit]
		if current == nil {
			return false
		}
	}
	return current.isPrefix
}

var (
	proxyTrie  IPPrefixTrie
	signToken  string
	hmacPool   sync.Pool
	bufferPool sync.Pool
)

const (
	MaxXFFLength = 4096
	MaxXFFHops   = 32
)

func initConfig() {
	if err := loadTrustedProxies("proxy_cidr.txt"); err != nil {
		log.Fatalf("Failed to load proxy_cidr.txt: %v", err)
	}

	signToken = os.Getenv("SIGN_TOKEN")
	if signToken != "" {
		hmacPool = sync.Pool{
			New: func() any {
				return hmac.New(sha256.New, []byte(signToken))
			},
		}
		bufferPool = sync.Pool{
			New: func() any {
				b := make([]byte, 0, 512)
				return &b
			},
		}
	}
}

func loadTrustedProxies(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			continue
		}
		proxyTrie.Insert(prefix)
	}
	return scanner.Err()
}

func getRealIP(r *http.Request, w http.ResponseWriter) (string, bool) {
	remoteAddrPort, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return "", false
	}
	
	remoteIP := remoteAddrPort.Addr().Unmap()

	if !proxyTrie.Contains(remoteIP) {
		return remoteIP.String(), true
	}

	// 使用 Values 获取所有 XFF，防御 HTTP Header Splitting 攻击
	xffHeaders := r.Header.Values("X-Forwarded-For")
	if len(xffHeaders) == 0 {
		return remoteIP.String(), true
	}

	// 严密风控：优先校验所有 XFF 头部总长度，杜绝多条小 Header 累加导致的资源耗尽
	totalXFFLen := 0
	for _, xff := range xffHeaders {
		totalXFFLen += len(xff)
	}
	if totalXFFLen > MaxXFFLength {
		w.WriteHeader(http.StatusBadRequest)
		return "", false
	}

	lastValidIP := remoteIP
	hopCount := 0

	// 从最后一个 Header 开始逆向溯源
	for hIdx := len(xffHeaders) - 1; hIdx >= 0; hIdx-- {
		remaining := xffHeaders[hIdx]

		// 零分配游标截取
		for len(remaining) > 0 {
			hopCount++
			if hopCount > MaxXFFHops {
				w.WriteHeader(http.StatusBadRequest)
				return "", false
			}

			var ipStr string
			idx := strings.LastIndexByte(remaining, ',')
			if idx == -1 {
				ipStr = strings.TrimSpace(remaining)
				remaining = ""
			} else {
				ipStr = strings.TrimSpace(remaining[idx+1:])
				remaining = remaining[:idx]
			}

			if ipStr == "" {
				continue
			}

			addr, err := netip.ParseAddr(ipStr)
			if err != nil {
				return lastValidIP.String(), true
			}

			addr = addr.Unmap()

			if !proxyTrie.Contains(addr) {
				return addr.String(), true
			}
			lastValidIP = addr
		}
	}

	return lastValidIP.String(), true
}

func signAndWriteResponse(w http.ResponseWriter, ip string) {
	if signToken == "" {
		io.WriteString(w, ip)
		return
	}

	bufPtr := bufferPool.Get().(*[]byte)
	buf := (*bufPtr)[:0]

	buf = append(buf, ip...)
	buf = append(buf, '|')
	buf = strconv.AppendInt(buf, time.Now().UnixMilli(), 10)
	rawPayloadEnd := len(buf)

	// 严密的容量计算：计算 Base64 需要的长度 + 1 个 '.' + Hex 签名长度 + 哈希所需的冗余空间
	b64Len := base64.StdEncoding.EncodedLen(rawPayloadEnd)
	neededTotal := b64Len + 1 + hex.EncodedLen(sha256.Size)
	encodeNeed := rawPayloadEnd + b64Len
	if encodeNeed > neededTotal {
		neededTotal = encodeNeed
	}

	if cap(buf) < neededTotal {
		newBuf := make([]byte, neededTotal)
		copy(newBuf, buf)
		buf = newBuf
	}

	// In-place 原地 Base64 编码
	b64Start := rawPayloadEnd
	buf = buf[:b64Start+b64Len]
	base64.StdEncoding.Encode(buf[b64Start:], buf[:rawPayloadEnd])

	h := hmacPool.Get().(hash.Hash)
	h.Write(buf[b64Start:])

	// 移位并插入 '.' 分隔符
	copy(buf[0:b64Len], buf[b64Start:])
	buf[b64Len] = '.'
	buf = buf[:b64Len+1]

	// 利用逃逸分析，在栈上申请固定大小数组接收哈希，杜绝堆分配和内存覆写
	var sumBuf [sha256.Size]byte
	sum := h.Sum(sumBuf[:0])
	
	buf = hex.AppendEncode(buf, sum)

	w.Write(buf)

	// 手动清理对象，拔掉 defer 开销
	h.Reset()
	hmacPool.Put(h)

	*bufPtr = buf
	bufferPool.Put(bufPtr)
}

func ipHandler(w http.ResponseWriter, r *http.Request) {
	realIP, ok := getRealIP(r, w)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	signAndWriteResponse(w, realIP)
}

func main() {
	initConfig()

	server := &http.Server{
		Addr:              ":8080",
		Handler:           http.HandlerFunc(ipHandler),
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      2 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	log.Printf("Production Ready Radix-Trie Edge Server running...")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
