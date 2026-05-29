# Get Real IP Service 🚀

一个专为高并发网关和边缘计算节点设计的**极速、安全、防伪造**的真实客户端 IP 提取与签名服务。

当你的应用部署在 CDN（如 Cloudflare、AWS CloudFront）或多层反向代理之后时，直接读取 `RemoteAddr` 只能获取到代理节点的 IP，而盲目信任 `X-Forwarded-For` (XFF) Header 则极易遭到客户端的 IP 伪造攻击。

本项目通过严格解析代理链并结合 HMAC-SHA256 密码学签名，完美解决这一痛点，安全地将真实客户端 IP 传递给你的下游业务。

## ✨ 核心特性

* ⚡️ **极致性能 (Extreme Performance)**: 基于 Go 1.23 原生 `net/netip` 库开发，全程无锁 (Lock-Free)。核心 XFF 解析逻辑实现**零堆内存分配 (Zero-Allocation)**，并利用 `sync.Pool` 复用底层加密对象，彻底消除高并发下的 GC 停顿，单机可轻松扛下数万至十万级 RPS。
* 🛡️ **绝对安全 (High Security)**: 严格遵循代理溯源原则，从右向左逐级回溯 `X-Forwarded-For`。一旦遇到不在可信 CDN 白名单中的节点，立刻切断信任链并将其判定为真实客户端，彻底杜绝恶意用户通过伪造 Header 绕过 IP 限制。
* ✍️ **防篡改签名 (Anti-Tampering)**: 支持对提取到的真实 IP 进行 HMAC-SHA256 签名，输出 `base64(IP|timestamp).signature` 格式。下游服务可轻松验签，确保 IP 在内网传输过程中未被篡改。
* 🌐 **双栈支持 (IPv4 & IPv6)**: 底层统一数据结构，原生且高性能地同时处理 IPv4 和 IPv6 流量及网段校验。
* 📦 **开箱即用 (Out of the Box)**: 镜像内置了常见的权威 CDN（如 Cloudflare、AWS CloudFront）IP 段列表，可以直接启动。同时支持灵活的自定义挂载。
* 🐳 **极小体积 (Micro Image)**: 采用纯静态编译与多阶段构建，基于 Alpine 的多架构 (amd64/arm64) Docker 镜像体积仅数 MB。

---

## 🚀 Docker 部署指南

本服务推荐使用 Docker 进行部署，直接拉取 Github Container Registry 上的预构建镜像即可。

### 方式一：使用内置的默认 CDN 节点配置（最简单）

镜像内部已经打包了一份默认的 `proxy_cidr.txt`（包含 Cloudflare 和 CloudFront 的官方 IP 段以及本地局域网段）。如果你只需要这些基础防护，直接运行：

```bash
docker run -d \
  --name get-real-ip \
  --restart always \
  -p 8080:8080 \
  -e SIGN_TOKEN="your_super_secret_token_here" \
  ghcr.io/jbtt-2025/get-real-ip:latest
```

### 方式二：挂载自定义的代理节点配置（推荐生产环境）

在复杂的生产环境中，你可能使用了其他 CDN 厂商，或者有自建的 WAF/代理集群。此时你需要自己维护一份可信 IP 列表，并通过 `-v` 参数将其挂载到容器内部覆盖默认配置。

1. 在宿主机创建一个 `proxy_cidr.txt` 文件，一行一个 CIDR（支持 IPv4/IPv6）：

   ```text
   # 内部 WAF 节点
   10.0.0.0/8
   192.168.1.0/24

   # 某个特定的第三方 CDN 节点
   123.45.67.0/24
   2400:cb00::/32
   ```

2. 启动容器并挂载该文件：

   ```bash
   docker run -d \
     --name get-real-ip \
     --restart always \
     -p 8080:8080 \
     -v $(pwd)/proxy_cidr.txt:/root/proxy_cidr.txt:ro \
     -e SIGN_TOKEN="your_super_secret_token_here" \
     ghcr.io/jbtt-2025/get-real-ip:latest
   ```

### 方式三：Host 网络模式直接监听 80（高并发推荐）

如果你的部署目标是极高并发，并且这台机器只运行该服务，推荐使用 Docker `host` 网络模式，让 Go 服务直接监听宿主机端口。

这种方式可以绕过 Docker 端口映射带来的 DNAT / conntrack 开销，减少高并发短连接场景下的网络层压力。

> 注意：`--network host` 模式下不要再使用 `-p` 参数，容器会直接使用宿主机网络栈。

```bash
docker run -d \
  --name get-real-ip \
  --restart always \
  --network host \
  -e LISTEN_ADDR=":80" \
  -e SIGN_TOKEN="your_super_secret_token_here" \
  ghcr.io/jbtt-2025/get-real-ip:latest
```

如果你需要同时挂载自定义代理节点配置：

```bash
docker run -d \
  --name get-real-ip \
  --restart always \
  --network host \
  -v $(pwd)/proxy_cidr.txt:/root/proxy_cidr.txt:ro \
  -e LISTEN_ADDR=":80" \
  -e SIGN_TOKEN="your_super_secret_token_here" \
  ghcr.io/jbtt-2025/get-real-ip:latest
```

适用场景：

```text
高 QPS
短连接很多
不需要 nginx 再反代本服务
希望降低 Docker NAT / conntrack 压力
```

不适用场景：

```text
宿主机 80 端口已经被 nginx / aaPanel / 其他服务占用
需要通过 Docker -p 做端口映射隔离
同一台机器上有多个服务需要共享 80 端口
```

### ⚙️ 环境变量说明

| 变量名 | 描述 | 默认值 |
| :--- | :--- | :--- |
| `SIGN_TOKEN` | 用于 HMAC-SHA256 签名的密钥。**强烈建议设置**。如果留空，服务将关闭签名功能，仅返回明文的真实 IP。 | (空) |
| `LISTEN_ADDR` | 服务监听地址。普通 Docker 端口映射模式下通常保持默认即可；Host 网络模式下可设置为 `:80` 让服务直接监听宿主机 80 端口。 | `:8080` |

---

## 🔍 输出格式与下游验证

### 服务输出格式

当配置了 `SIGN_TOKEN` 时，访问服务（`http://localhost:8080/`）将返回如下格式的纯文本串：

```text
[Base64编码的真实IP与时间戳].[HMAC-SHA256签名(Hex)]
```

**示例：**

```text
MTI3LjAuMC4xfDE3NzkzNjAxNzk1Mzc=.573d3552599c61fabc54719f81a4fb2bf626e734a2996052efb20858cd00d36d
```

Base64 解码后格式为：

```text
127.0.0.1|1779360179537
```

其中 `|` 前半部分是真实客户端 IP，后半部分是毫秒级 Unix 时间戳。

### 下游业务如何验签？

为了保证安全，你的后端业务逻辑（如 PHP, Python, Java, Node.js 等）获取到上述字符串后，应按以下逻辑处理：

1. 以 `.` 为分隔符，将字符串拆分为 `Payload`（前半部分）和 `Signature`（后半部分）。
2. 使用你与本服务约定好的同一个 `SIGN_TOKEN`，对 `Payload` 进行 HMAC-SHA256 运算，并将结果转为 Hex 字符串。
3. 对比你计算出的 Hex 字符串与收到的 `Signature` 是否完全一致。
4. 如果一致，说明 Payload 未被篡改且确实来源于本服务。
5. 对 `Payload` 进行 Base64 解码，得到 `真实IP|时间戳`。
6. 根据业务需要校验时间戳是否在允许窗口内，再使用其中的真实客户端 IP。

---

## 🛠️ 测试连通性

服务启动后，你可以使用 `curl` 模拟带有伪造 XFF 的请求来验证防御逻辑：

```bash
# 模拟普通请求
curl http://localhost:8080/

# 模拟带有伪造代理链的恶意请求
# 只有当 8.8.8.8 不在 proxy_cidr.txt 中时，程序会正确截断并识别出实际来源 IP 或最后一个可信代理。
curl -H "X-Forwarded-For: 1.1.1.1, 8.8.8.8" http://localhost:8080/
```

如果你使用 Host 网络模式并设置了 `LISTEN_ADDR=":80"`，测试地址应改为：

```bash
curl http://localhost/
curl -H "X-Forwarded-For: 1.1.1.1, 8.8.8.8" http://localhost/
```
