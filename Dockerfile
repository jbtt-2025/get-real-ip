# --- Build Stage ---
FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod ./
# 由于没有第三方依赖，go mod download 实际上很快就结束了。
# 如果未来引入了外部库（生成了 go.sum），请将其改为 COPY go.mod go.sum ./
RUN go mod download

# 复制源代码及配置文件 (包括 main.go 和 proxy_cidr.txt)
COPY . .

# 构建 Go 应用
# -ldflags="-w -s" 用于减小二进制文件大小（去除调试信息）
# CGO_ENABLED=0 用于静态链接，确保在 Alpine 等最小镜像中没有 C 依赖问题
# 这里不写死 GOARCH，方便 GitHub Actions (buildx) 自动根据目标平台 (arm64/amd64) 注入环境变量编译
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/realip-server ./main.go

# --- Runtime Stage ---
FROM alpine:latest

# 安装 CA 证书和时区数据（生产环境跑后端服务时的最佳实践）
RUN apk --no-cache add ca-certificates tzdata

# 设置工作目录
WORKDIR /root/

# 从 builder 阶段复制编译好的可执行文件
COPY --from=builder /app/realip-server .

# 从 builder 阶段复制 CDN 代理 IP 列表
COPY --from=builder /app/proxy_cidr.txt .

# 暴露服务端口
EXPOSE 8080

# 启动服务
CMD ["./realip-server"]
