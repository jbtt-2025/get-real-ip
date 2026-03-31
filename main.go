package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strings"
)

var trustedProxies []netip.Prefix

// initTrustedProxies 加载 CIDR，原生兼容 IPv4 和 IPv6
func initTrustedProxies(filePath string) error {
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
			log.Printf("警告: 无法解析 CIDR '%s', 错误: %v", line, err)
			continue
		}
		trustedProxies = append(trustedProxies, prefix)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	log.Printf("成功加载 %d 个可信 CDN CIDR (支持 IPv4/IPv6)", len(trustedProxies))
	return nil
}

// isTrustedProxy 检查 IP 是否在可信列表中 (支持 IPv4/IPv6)
func isTrustedProxy(ip netip.Addr) bool {
	for _, prefix := range trustedProxies {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// getRealIP 核心逻辑：从 X-Forwarded-For 中安全提取真实 IP
func getRealIP(r *http.Request) string {
	// 1. 获取物理直连对端 IP
	remoteAddrPort, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return "" // 防御性兜底
	}
	remoteIP := remoteAddrPort.Addr()

	// 2. 如果直连 IP 不在白名单中，说明它没有经过受信任的代理
	// 直接判定它就是客户端 IP，抛弃所有 Header
	if !isTrustedProxy(remoteIP) {
		return remoteIP.String()
	}

	// 3. 直连 IP 可信，开始解析 X-Forwarded-For
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		// 虽然来自信任代理，但没有传递 XFF，只能返回代理的 IP
		return remoteIP.String()
	}

	ips := strings.Split(xff, ",")
	lastValidIP := remoteIP

	// 从右向左遍历 XFF (从最靠近我们的代理开始往客户端方向回溯)
	for i := len(ips) - 1; i >= 0; i-- {
		ipStr := strings.TrimSpace(ips[i])
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			// 如果遇到格式错误的 IP（被恶意篡改或解析失败），信任链断裂。
			// 返回上一个已知合法的节点 IP。
			return lastValidIP.String()
		}

		// 如果当前遍历到的 IP 不是信任的代理，说明我们找到了真实的客户端
		if !isTrustedProxy(addr) {
			return addr.String()
		}

		// 当前 IP 也是信任代理，更新最后一次看到的有效 IP，继续向左寻找
		lastValidIP = addr
	}

	// 兜底：如果 XFF 里的所有 IP 全是受信任的代理，返回最左边的那个合法代理 IP
	return lastValidIP.String()
}

func ipHandler(w http.ResponseWriter, r *http.Request) {
	realIP := getRealIP(r)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "Your Real IP: %s\n", realIP)
}

func main() {
	if err := initTrustedProxies("proxy_cidr.txt"); err != nil {
		log.Fatalf("初始化代理列表失败: %v\n请确保当前目录下存在 proxy_cidr.txt 文件。", err)
	}

	http.HandleFunc("/", ipHandler)

	port := "8080"
	log.Printf("服务启动，监听端口: %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
