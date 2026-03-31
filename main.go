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
	"strings"
	"sync"
)

var (
	trustedProxies []netip.Prefix
	signToken      string
	hmacPool       sync.Pool
)

// initConfig 初始化配置和环境变量
func initConfig() {
	if err := loadTrustedProxies("proxy_cidr.txt"); err != nil {
		log.Fatalf("Failed to load proxy_cidr.txt: %v", err)
	}

	signToken = os.Getenv("SIGN_TOKEN")
	if signToken == "" {
		log.Println("警告: SIGN_TOKEN 环境变量未设置，将跳过签名逻辑")
	} else {
		// 初始化 HMAC 对象池，极大地减少高并发下的 GC 压力
		hmacPool = sync.Pool{
			New: func() any {
				return hmac.New(sha256.New, []byte(signToken))
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
			log.Printf("Skip invalid CIDR: %s", line)
			continue
		}
		trustedProxies = append(trustedProxies, prefix)
	}
	return scanner.Err()
}

// isTrustedProxy 线性扫描检查信任列表 (由于 netip.Prefix.Contains 是位运算，百级别以内性能极高)
func isTrustedProxy(ip netip.Addr) bool {
	for i := 0; i < len(trustedProxies); i++ {
		if trustedProxies[i].Contains(ip) {
			return true
		}
	}
	return false
}

// getRealIP 核心优化：零内存分配 (Zero-Allocation) 的 XFF 解析
func getRealIP(r *http.Request) string {
	remoteAddrPort, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	remoteIP := remoteAddrPort.Addr()

	if !isTrustedProxy(remoteIP) {
		return remoteIP.String()
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return remoteIP.String()
	}

	lastValidIP := remoteIP
	remaining := xff

	// 从右向左手动遍历字符串，彻底避免 strings.Split 带来的切片内存分配
	for len(remaining) > 0 {
		var ipStr string
		idx := strings.LastIndexByte(remaining, ',')
		
		if idx == -1 {
			// 没有逗号了，剩下的是最左边的 IP
			ipStr = strings.TrimSpace(remaining)
			remaining = ""
		} else {
			// 提取最后一个逗号右边的 IP
			ipStr = strings.TrimSpace(remaining[idx+1:])
			// 将游标向前移动
			remaining = remaining[:idx]
		}

		if ipStr == "" {
			continue
		}

		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			// 遇到无效格式，信任链断裂
			return lastValidIP.String()
		}
		if !isTrustedProxy(addr) {
			// 找到非代理 IP，即真实客户端
			return addr.String()
		}
		lastValidIP = addr
	}

	return lastValidIP.String()
}

// signIP 核心优化：复用底层加密对象，避免 fmt.Sprintf
func signIP(ip string) string {
	if signToken == "" {
		return ip
	}

	// Base64 编码 (这一步由于需要生成新字符串，必须分配一次内存)
	b64IP := base64.StdEncoding.EncodeToString([]byte(ip))

	// 从对象池借出一个 HMAC 实例
	h := hmacPool.Get().(hash.Hash)
	
	// 用完后清理并归还给对象池
	defer func() {
		h.Reset()
		hmacPool.Put(h)
	}()

	h.Write([]byte(b64IP))
	// hex.EncodeToString 底层也有极小的分配，但在对象池加持下已经极其高效
	signature := hex.EncodeToString(h.Sum(nil))

	// 使用原生 + 拼接，比 fmt.Sprintf 更快
	return b64IP + "." + signature
}

func ipHandler(w http.ResponseWriter, r *http.Request) {
	realIP := getRealIP(r)
	if realIP == "" {
		http.Error(w, "Unable to determine IP", http.StatusInternalServerError)
		return
	}

	result := signIP(realIP)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// 使用 io.WriteString 直接写入，省去字符串到 []byte 的转换开销
	io.WriteString(w, result)
}

func main() {
	initConfig()

	// 禁用 Keep-Alive 中的额外开销（可选，根据你的网关架构决定）
	// 如果前端有 Nginx 保持长连接，这里可以保留默认。
	server := &http.Server{
		Addr:    ":8080",
		Handler: http.HandlerFunc(ipHandler),
	}

	log.Printf("Optimized Server starting on port 8080")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
