FROM alpine:latest

# 安装基础运行环境（时区数据、证书）
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# 根据构建架构自动选择复制对应的二进制文件
ARG TARGETARCH
COPY vane-linux-${TARGETARCH} /app/vane

RUN chmod +x /app/vane

# 映射数据目录
VOLUME ["/app/data"]

# 暴露 dashboard 默认端口
EXPOSE 4455

# 启动命令，默认指定数据路径为 /app/data
ENTRYPOINT ["/app/vane"]
