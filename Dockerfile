FROM alpine:latest

# 安装基础库，如时区数据和证书（用于 HTTPS 请求）
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# 使用 buildx 提供的变量自动识别架构
ARG TARGETARCH
# 将前面步骤生成的二进制文件复制到容器内
# 这里假设二进制文件命名为 vane-linux-amd64 和 vane-linux-arm64
COPY vane-linux-${TARGETARCH} /app/vane

RUN chmod +x /app/vane

# 按照你的要求，默认数据路径为 /app/data
VOLUME ["/app/data"]

# 暴露端口
EXPOSE 4455

# 启动命令，默认加上 --config 参数
ENTRYPOINT ["/app/vane", "--config", "/app/data"]
