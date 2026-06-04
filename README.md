# sma11sCan

基于 Go 开发的高并发端口扫描 + 资产探测工具，支持端口扫描、Banner 抓取、HTTP 探测、Web 指纹识别、Favicon 识别、服务识别和子域名收集。

## 功能清单

### 端口扫描
- TCP Connect 端口扫描
- 三种扫描模式：Fast（48 常用端口）/ Top（1000 端口）/ Full（1-65535）
- 单 IP 扫描、CIDR 网段扫描
- 域名自动解析为 IP，**SNI 正确设置**（TCP 连 IP，TLS 握手用域名）
- Worker Pool 并发控制（100 Worker），进度条实时显示

### Banner & 指纹
- **Banner 抓取**：TCP 连接后读取服务初始 Banner，自动清洗二进制数据
- **HTTP/HTTPS 探测**：模拟浏览器请求头，自定义 DialContext 实现 IP 连接 + 域名 SNI，提取状态码、Server 头、Cookies 和网页 Title
- **Web 指纹识别**：100+ 规则覆盖 Web Server / CMS / Framework / OA / CDN / DevOps，三级权重累积 + 阈值过滤，降低误报
- **Favicon 识别**：从 HTML 提取 favicon 路径，下载后计算 MD5 哈希，与指纹库匹配
- **服务识别**：Banner 关键词匹配（SSH/MySQL/Redis/VMware 等 15+ 种服务）+ 端口表兜底

### 子域名收集
- **DNS 字典爆破**：加载字典文件，并发 DNS 解析（50 并发），发现存活子域名
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
| `-banner`   | `false`          | 抓取 Banner 并识别服务 + Web 指纹                           |
| `-domain`   | -                | 目标域名，收集子域名                                        |
| `-wordlist` | `subdomains.txt` | 子域名爆破字典文件                                          |
| `-noscan`   | `false`          | 只收集子域名，不扫描端口                                    |

## 使用示例

### 端口扫描

```bash
# Fast 模式（48 常用端口）
go run . -ip 192.168.1.1 -module fast

# Top 1000 端口 + Banner + 指纹识别
go run . -ip 192.168.1.1 -module top -banner

# 全端口扫描（1-65535）
go run . -ip 192.168.1.1 -module full

# 域名扫描（自动解析，SNI 正确）
go run . -ip www.baidu.com -module fast -banner

# CIDR 网段扫描
go run . -ip 192.168.1.0/24 -banner
```

### 子域名收集

```bash
# 字典爆破子域名
go run . -domain baidu.com

# 只收集子域名，不扫描端口
go run . -domain baidu.com -noscan

# 子域名 + 端口扫描 + 指纹
go run . -domain baidu.com -module top -banner
```

### 输出示例

```
存活的端口：
192.168.31.1:80     [HTTP   ] <Nginx> 200 OK | Server: nginx/1.12.2 | Title: 小米路由器
183.2.172.177:80    [HTTP   ] 200 OK | Server: BWS/1.1 | Title: 百度一下，你就知道
42.247.24.130:443   [HTTP   ] 200 OK | Server: ****** | Title: 安徽财贸职业学院
192.168.31.219:22   [SSH    ] SSH-2.0-OpenSSH_8.2
192.168.31.202:3306 [MySQL  ] 8.0.43 caching_sha2_password
```

## 项目结构

```
├── main.go           # 入口，CLI 参数解析与流程控制
├── scanner.go        # 扫描核心（端口探测、Worker Pool、CIDR 解析、域名解析、结果输出）
├── scan_modle.go     # 端口列表（Fast 48 / Top 1000 / Full）+ 三种扫描函数
├── banner.go         # Banner 抓取、HTTP/HTTPS 探测（SNI 修复）、Banner 清洗、服务识别
├── fingerprinter.go  # Web 指纹规则库（100+ 规则）+ 权重匹配引擎 + Favicon 识别
├── subdomain.go      # 子域名收集（crt.sh + DNS 字典爆破）
└── subdomains.txt    # 默认子域名爆破字典
```

## 技术实现

- **并发控制**：全端口使用 Worker Pool + Channel，100 Worker 并行；子域名使用信号量限制 50 并发
- **Banner 抓取**：TCP 连接后 `conn.Read` 读取初始 Banner，`CleanBanner` 清洗二进制数据
- **HTTP 探测**：自定义 `DialContext`（TCP 连 IP）+ `ServerName`（TLS SNI 用域名），模拟浏览器请求头（UA/Accept/Accept-Language），正则提取 `<title>`
- **Web 指纹识别**：`Matchfinger` 权重累积引擎 — 铁证(90-100) 单条过，正文(70-85) 基本过，辅助(25-60) 需多信号叠加；`MatchFavicon` 独立 favicon hash 匹配
- **Favicon 识别**：从 HTML 正则提取 `<link icon>` → MD5 哈希 → 与 `FaviconDB` 指纹库匹配
- **服务识别**：`BannerIdentify` 三层策略 — Banner 关键词匹配 → 端口查表 `Top_port()` 兜底 → Unknown
- **域名解析**：`ResolveHost` 自动识别 IP/域名，域名调用 `net.LookupHost` 解析
- **子域名爆破**：并发 DNS 解析，50 信号量控制，Mutex 共享结果
- **进度条**：`atomic` 原子计数器 + `\r` 原地刷新

## License

MIT
