# sma11sCan

基于 Go 开发的高并发端口扫描工具，支持单 IP / CIDR 网段扫描、Banner 抓取、HTTP 探测和服务识别。

## 功能

- [√] TCP Connect 端口扫描
- [√] 单 IP 扫描
- [√] CIDR 网段扫描
- [√] Top 常用端口快速扫描（48 个端口）
- [√] 全端口扫描（1-65535）
- [√] 协程并发，Worker Pool 控制并发数
- [√] 进度条显示
- [√] Banner 抓取（TCP 主动 Banner + HTTP/HTTPS 探测）
- [√] 服务识别（Banner 关键词匹配 + 端口表兜底）
- [√] CLI 命令行参数

## 快速开始

```bash
# 克隆项目
git clone https://github.com/shen060606/sma11sCan.git
cd sma11sCan

# 查看帮助
go run . -h
```

## 使用说明

### 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-ip` | (必填) | 目标 IP 地址或 CIDR 网段 |
| `-module` | `top` | 扫描模式：`top`(常用端口) / `full`(全端口) |
| `-banner` | `false` | 抓取服务 Banner 信息 |

### 单 IP 扫描

```bash
# Top 端口扫描
go run . -ip 192.168.1.1 -module top

# 全端口扫描
go run . -ip 192.168.1.1 -module full

# 带 Banner 抓取
go run . -ip 192.168.1.1 -module top -banner
```

### 网段扫描（默认 Top 端口）

```bash
go run . -ip 192.168.31.0/24

# 网段 + Banner
go run . -ip 192.168.1.0/24 -banner
```

### 扫描模式

| 模式 | 说明 | 端口数 |
|------|------|--------|
| Top 端口 | 常见服务端口（SSH/HTTP/MySQL 等） | 48 |
| 全端口 | 完整 1-65535 | 65535 |

### 输出示例

```
存活的端口：
127.0.0.1:22    SSH     SSH-2.0-OpenSSH_8.1
127.0.0.1:80    http    200 OK | Server: nginx | Title: Welcome
127.0.0.1:443   https   404 Not Found
127.0.0.1:3306  MySQL   8.0.30 caching_sha2_password
127.0.0.1:902   VMware  220 VMware Authentication Daemon Version 1.10
```

## 项目结构

```
├── main.go          # 入口，CLI 参数与流程控制
├── scanner.go       # 扫描核心（端口探测、Worker Pool、CIDR 解析、结果输出）
├── scan_modle.go    # 扫描模式（Top 端口列表、全端口扫描）
└── banner.go        # Banner 抓取、HTTP Probe、服务识别
```

## 技术实现

- **并发控制**：全端口扫描使用 Worker Pool + Channel，100 个 Worker 并行
- **Banner 抓取**：TCP 连接后读取初始 Banner，支持清洗二进制数据
- **HTTP 探测**：对 80/443/8080 等端口主动发送 HTTP GET 请求，提取状态码、Server 头和 Title
- **HTTPS 支持**：跳过证书验证，自动 TLS 握手
- **服务识别**：Banner 关键词匹配（SSH/MySQL/Redis/VMware 等）+ 端口表兜底
- **网段扫描**：外层 Goroutine 并发扫每个 IP，内层各自跑扫描模式
- **进度条**：`atomic` 原子计数器 + `\r` 原地刷新

## License

MIT
