FROM golang:alpine AS builder

# 安装 C 编译器（SQLite CGO 需要）
ENV CGO_ENABLED=1
ENV GOPROXY=https://goproxy.cn,direct
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    && apk add --no-cache gcc musl-dev

WORKDIR /build

# 先复制依赖文件，利用 Docker 缓存
COPY go.mod go.sum ./
RUN go mod download

# 再复制全部源码
COPY . .

# 编译 API 服务
RUN go build -ldflags="-s -w" -o sma11scan-api ./cmd/sma11scan-api/

# ============================================
# 运行时镜像
# ============================================
FROM alpine:latest

# 换国内镜像源（加速 apk 安装）
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    && apk add --no-cache ca-certificates tzdata

WORKDIR /app

# 从构建阶段复制二进制
COPY --from=builder /build/sma11scan-api /app/sma11scan-api

# 复制静态资源和字典
COPY --from=builder /build/static        /app/static
COPY --from=builder /build/subdomains.txt /app/subdomains.txt

# 数据库持久化目录
VOLUME ["/app/data"]

EXPOSE 8088

ENTRYPOINT ["./sma11scan-api"]
