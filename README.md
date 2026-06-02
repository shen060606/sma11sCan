# sma11sCan

基于 Go 开发的高并发端口扫描 + 资产探测工具，支持端口扫描、Banner 抓取、HTTP 探测、服务识别和子域名收集。

## 功能

### 端口扫描
- TCP Connect 端口扫描
- 三种扫描模式：Fast（48 常用端口）/ Top（1000 端口）/ Full（1-65535）
- 单 IP 扫描、CIDR 网段扫描
- 域名自动解析为 IP
- Worker Pool 并发控制（100 Worker），进度条实时显示

### 资产探测
- **Banner 抓取**：TCP 连接后读取服务初始 Banner，自动清洗二进制数据
- **HTTP/HTTPS 探测**：对 HTTP 端口主动发送 GET 请求，提取状态码、Server 头和网页 Title
- **服务识别**：Banner 关键词匹配（SSH/MySQL/Redis/VMware 等 15+ 种服务）+ 端口表兜底

### 子域名收集
- **DNS 字典爆破**：加载字典文件，并发 DNS 解析，发现存活子域名
- **crt.sh 证书日志**（备选）：通过证书透明度日志获取子域名
- 子域名收集后可联动端口扫描

## 快速开始

```bash
git clone https://github.com/shen060606/sma11sCan.git
cd sma11sCan
go run . -h
```

## 命令行参数

| 参数        | 默认值           | 说明                                                        |
| ----------- | ---------------- | ----------------------------------------------------------- |
| `-ip`       | (必填)           | 目标 IP/域名/CIDR 网段                                      |
| `-module`   | `fast`           | 扫描模式：`fast`(48端口) / `top`(1000端口) / `full`(全端口) |
| `-banner`   | `false`          | 抓取服务 Banner 并识别服务                                  |
| `-domain`   | —                | 目标域名，收集子域名                                        |
| `-wordlist` | `subdomains.txt` | 子域名爆破字典文件                                          |
| `-noscan`   | `false`          | 只收集子域名，不扫描端口                                    |

## 使用示例

### 端口扫描

```bash
# Fast 模式（48 常用端口）
go run . -ip 192.168.1.1 -module fast

# Top 1000 端口 + Banner 抓取
go run . -ip 192.168.1.1 -module top -banner

# 全端口扫描（1-65535）
go run . -ip 192.168.1.1 -module full

# 域名扫描（自动解析）
go run . -ip baidu.com -module top -banner

# CIDR 网段扫描
go run . -ip 192.168.1.0/24 -banner
```

### 子域名收集

```bash
# 字典爆破子域名（默认用 subdomains.txt）
go run . -domain baidu.com

# 只收集子域名，不扫描端口
go run . -domain baidu.com -noscan

# 子域名 + 端口扫描
go run . -domain baidu.com -module top -banner

# 指定字典文件
go run . -domain baidu.com -wordlist big.txt
```

### 输出示例

```
存活的端口：
127.0.0.1:22    SSH     SSH-2.0-OpenSSH_8.1
127.0.0.1:80    HTTP    200 OK | Server: nginx | Title: Welcome
127.0.0.1:443   HTTPS   404 Not Found
127.0.0.1:3306  MySQL   8.0.30 caching_sha2_password
127.0.0.1:902   VMware  220 VMware Authentication Daemon Version 1.10

收集到 15 个子域名：
  www.baidu.com
  mail.baidu.com
  api.baidu.com
  ...
```

## 项目结构

```
├── main.go          # 入口，CLI 参数解析与流程控制
├── scanner.go       # 扫描核心（端口探测、Worker Pool、CIDR 解析、域名解析、结果输出）
├── scan_modle.go    # 端口列表（Fast 48 / Top 1000 / Full）+ 三种扫描函数
├── banner.go        # Banner 抓取、HTTP/HTTPS 探测、Banner 清洗、服务识别
├── subdomain.go     # 子域名收集（crt.sh + DNS 字典爆破）
└── subdomains.txt   # 默认子域名爆破字典
```

## 技术实现

- **并发控制**：全端口使用 Worker Pool + Channel，100 Worker 并行；子域名使用信号量限制 50 并发
- **Banner 抓取**：TCP 连接后 `conn.Read` 读取初始 Banner，`CleanBanner` 清洗二进制数据
- **HTTP 探测**：`http.Client` 发送 GET 请求（443 自动走 TLS + 跳过证书验证），正则提取 `<title>`
- **服务识别**：`BannerIdentify` 三层策略 — Banner 关键词匹配 → 端口查表 `Top_port()` 兜底 → Unknown
- **域名解析**：`ResolveHost` 自动识别 IP/域名，域名调用 `net.LookupHost` 解析
- **子域名爆破**：并发 DNS 解析，50 信号量控制，Mutex 共享结果
- **进度条**：`atomic` 原子计数器 + `\r` 原地刷新

## License

MIT
