# 构建阶段
FROM golang:1.24-alpine AS builder

# 设置工作目录
WORKDIR /app

# 复制go.mod和go.sum文件并下载依赖
COPY go.mod go.sum ./
RUN go mod download

# 复制项目代码
COPY . .

# 构建应用，禁用CGO以创建静态链接的二进制文件
RUN CGO_ENABLED=0 GOOS=linux go build -o keys-gin main.go

# 运行阶段，使用Alpine作为基础镜像
FROM alpine:3.20

# 安装必要的CA证书（用于HTTPS请求）
RUN apk --no-cache add ca-certificates

# 创建非root用户运行应用
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# 设置工作目录
WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/keys-gin .

# 复制配置文件
COPY config/config.yaml ./config/config.yaml

# 创建必要的目录并设置权限
RUN mkdir -p logs data && chown -R appuser:appgroup /app

# 切换到非root用户
USER appuser

# 暴露应用端口
EXPOSE 8080

# 设置启动命令
CMD ["./keys-gin"]