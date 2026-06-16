# sma11sCan

基于 Go 开发的高并发端口扫描 + 资产探测工具，支持端口扫描、Banner 抓取、HTTP 探测、Web 指纹识别、Favicon 识别、服务识别、子域名收集、**CDN 检测**和**源站 IP 找回**。同时提供 **Gin Web API 服务**，支持 Web 页面发起扫描和历史查询。

## 功能清单

### 端口扫描
- TCP Connect 端口扫描
- 三种扫描模式：`fast`（常用端口）/ `top`（Top 1000）/ `full`（1-65535）
- 单 IP 扫描、CIDR 网段扫描
- 域名自动解析为 IP，**SNI 正确设置**（TCP 连 IP，TLS 握手用域名）
- Worker Pool 并发控制（100 Worker），进度条实时显示

### CDN 检测 & 源站 IP 找回
- **CNAME CDN 检测**：通过 DNS CNAME 记录匹配 18 家国内外主流 CDN（阿里云、腾讯云、Cloudflare、Akamai、AWS CloudFront 等）
- **第三方历史 DNS 查询**：接入 [VirusTotal API](https://www.virustotal.com/) 获取域名历史解析 IP（需设置 `VT_API_KEY` 环境变量）
- **源站 IP 验证**：对候选 IP 发起 HTTP/HTTPS 请求（自动补全协议、Host 头覆写、TLS SNI 设置为原域名），比较 **网页 Title + Favicon 哈希** 双重验证
- 命中源站 IP 后自动切为真实 IP 扫描，绕过 CDN 直接探测后端服务

### Banner & 指纹
- **Banner 抓取**：TCP 连接后读取服务初始 Banner，自动清洗二进制数据
- **HTTP/HTTPS 探测**：模拟浏览器请求头，自定义 DialContext 实现 IP 连接 + 域名 SNI，提取状态码、Server 头、Cookies 和网页 Title
- **Web 指纹识别**：100+ 规则覆盖 Web Server / CMS / Framework / OA / CDN / DevOps，三级权重累积 + 阈值过滤，降低误报
- **Favicon 识别**：从 HTML 提取 favicon 路径（含相对路径自动拼接），下载后计算 MD5 哈希，与 50+ 指纹库匹配
- **服务识别**：Banner 关键词匹配（SSH/MySQL/Redis/RDP 等 15+ 种服务）+ 端口表兜底

### 子域名收集
- **DNS 字典爆破**：加载字典文件，并发 DNS 解析（50 并发），发现存活子域名
- **crt.sh 证书日志**（备选）：通过证书透明度日志获取子域名
- 子域名收集后可联动端口扫描

### Web API 服务（新增）
- **Gin Web 框架**：提供 RESTful API + 前端页面
- **网页发起扫描**：浏览器直接输入 IP/域名/CIDR，选择扫描模式
- **扫描历史查询**：SQLite 存储扫描结果，支持按批次查看历史记录
- 监听端口：`8088`

## 快速开始

### 下载 Release 二进制（推荐）

从 [Releases](https://github.com/shen060606/sma11sCan/releases) 页面下载对应的 `.exe` 文件，直接运行：

```bash
# CLI 命令行工具
.\sma11scan.exe -ip 192.168.1.1 -module fast

# Web API 服务（双击运行，浏览器访问 http://localhost:8088）
.\sma11scan-api.exe
```

### 从源码运行

```bash
git clone https://github.com/shen060606/sma11sCan.git
cd sma11sCan

# CLI 工具
go run ./cmd/sma11scan/ -h

# API 服务
go run ./cmd/sma11scan-api/
```

### 环境变量（可选）

| 变量         | 说明                                                     |
| ------------ | -------------------------------------------------------- |
| `VT_API_KEY` | VirusTotal API Key，用于获取域名历史 DNS 记录找回源站 IP |

```bash
# Windows (PowerShell)
$env:VT_API_KEY = "your-api-key"

# Linux / macOS
export VT_API_KEY="your-api-key"
```

不设置不影响其他功能，仅 CDN 源站找回需要。

### Docker（可选，仅供轻度体验）

```bash
# 构建镜像
docker build -t sma11scan-api .

# 启动
docker run -d -p 8088:8088 --name scan-api sma11scan-api

# 浏览器访问 http://localhost:8088
```

**Docker 限制说明**：由于 Docker Desktop（Windows/macOS）底层经过多层 NAT 转发，桥接网络下并发连接数受限，仅支持 **fast 模式扫描单个 IP/域名**。`top` 和 `full` 模式、CIDR 网段扫描、回环地址扫描在 Docker 中无法正常工作。如需完整扫描能力，请直接下载 Release 二进制在原生系统上运行。

> Linux 服务器上使用 `docker run --network host` 可解除上述限制。

## 命令行参数

| 参数        | 默认值           | 说明                                                          |
| ----------- | ---------------- | ------------------------------------------------------------- |
| `-ip`       | (必填)           | 目标 IP/域名/CIDR 网段。输入域名时自动进行 CDN 检测           |
| `-module`   | `fast`           | 扫描模式：`fast`(常用端口) / `top`(1000端口) / `full`(全端口) |
| `-banner`   | `false`          | 抓取 Banner 并识别服务 + Web 指纹                             |
| `-domain`   | -                | 目标域名，收集子域名                                          |
| `-wordlist` | `subdomains.txt` | 子域名爆破字典文件                                            |
| `-noscan`   | `false`          | 只收集子域名，不扫描端口                                      |

## 使用示例

### 端口扫描

```bash
# Fast 模式（常用端口）
.\sma11scan.exe -ip 192.168.1.1 -module fast

# Top 1000 端口 + Banner + 指纹识别
.\sma11scan.exe -ip 192.168.1.1 -module top -banner

# 全端口扫描（1-65535）
.\sma11scan.exe -ip 192.168.1.1 -module full

# 域名扫描（自动 CDN 检测 + 源站 IP 找回）
.\sma11scan.exe -ip www.baidu.com -module fast -banner

# CIDR 网段扫描
.\sma11scan.exe -ip 192.168.1.0/24 -banner
```

### CDN 检测 & 源站 IP 找回

```bash
# 设置 VirusTotal API Key
export VT_API_KEY="your-api-key"

# 扫描域名，自动检测 CDN 并尝试找回源站 IP
.\sma11scan.exe -ip www.example.com -module top -banner
```

输出示例：
```
[CNAME] www.example.com.cdn.cloudflare.net.
[CDN] true
[CDN Provider] Cloudflare
[VirusTotal] 获取到 5 个候选 IP
    1.2.3.4          source=VirusTotal  date=1717800000
    5.6.7.8          source=VirusTotal  date=1717700000
[Origin IP] 1.2.3.4
存活的端口：
1.2.3.4:80   [HTTP] 200 OK | Server: nginx/1.24.0 | Title: Example Site
1.2.3.4:443  [HTTP] 200 OK | Server: nginx/1.24.0 | Title: Example Site
```

- 未设置 `VT_API_KEY` 时，跳过 VirusTotal 查询，仍扫 CDN 节点
- 候选 IP 验证失败时，仍用 CDN 节点 IP 继续扫描

### 子域名收集

```bash
# 字典爆破子域名
.\sma11scan.exe -domain baidu.com

# 只收集子域名，不扫描端口
.\sma11scan.exe -domain baidu.com -noscan

# 子域名 + 端口扫描 + 指纹
.\sma11scan.exe -domain baidu.com -module top -banner
```

### Web API 服务

```bash
# 启动服务（双击 exe 或命令行运行均可）
.\sma11scan-api.exe
```

浏览器打开 `http://localhost:8088`：
- 首页：输入 IP/域名/CIDR，选择扫描模式，发起扫描
- 查询页：`/api/v1/scans` 查看历史扫描记录

API 接口：

| 方法 | 路径               | 说明                     |
| ---- | ------------------ | ------------------------ |
| GET  | `/`                | 首页（扫描表单）         |
| POST | `/api/v1/scan`     | 发起扫描                 |
| GET  | `/api/v1/scans`    | 历史查询页面             |
| GET  | `/api/v1/scans/list` | 扫描历史列表（JSON）   |

POST `/api/v1/scan` 请求示例：
```json
{
    "ip": "192.168.1.1",
    "module": "fast",
    "banner": false
}
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

## 构建 Release

```bash
# Windows
CGO_ENABLED=1 go build -ldflags="-s -w" -o sma11scan.exe ./cmd/sma11scan/
CGO_ENABLED=1 go build -ldflags="-s -w" -o sma11scan-api.exe ./cmd/sma11scan-api/

# Linux
CGO_ENABLED=1 go build -ldflags="-s -w" -o sma11scan ./cmd/sma11scan/
CGO_ENABLED=1 go build -ldflags="-s -w" -o sma11scan-api ./cmd/sma11scan-api/
```

> 注意：`CGO_ENABLED=1` 是必须的，因为项目依赖 SQLite（mattn/go-sqlite3）需要 CGO。

## 项目结构

```
├── cmd/
│   ├── sma11scan/
│   │   └── main.go                    # CLI 入口，参数解析与流程控制
│   └── sma11scan-api/
│       └── main.go                    # API 入口，Gin Web 服务
├── global/
│   ├── db.go                          # SQLite 数据库初始化（GORM）
│   ├── model.go                       # 数据模型定义
│   ├── saveresult_gorm.go             # 扫描结果持久化
│   ├── query.go                       # 历史查询逻辑
│   └── redis.go                       # Redis 客户端（预留）
├── internal/
│   ├── scanner/
│   │   ├── scanner.go                 # 扫描核心（端口探测、Worker Pool、CIDR 解析、域名解析、结果输出）
│   │   └── scan_model.go              # 端口列表 + 三种扫描模式 + 服务识别
│   ├── banner/
│   │   └── banner.go                  # Banner 抓取、HTTP/HTTPS 探测（SNI 修复）、Banner 清洗
│   ├── cdn/
│   │   └── cdn.go                     # CDN 检测（CNAME 匹配 18 家 CDN）、源站 IP 找回
│   ├── fingerprint/
│   │   └── fingerprint.go             # Web 指纹库（100+ 规则 + Favicon）+ 权重匹配引擎
│   └── subdomain/
│       └── subdomain.go               # 子域名收集（crt.sh + DNS 字典爆破）
├── static/
│   ├── index.html                     # 扫描表单页面
│   └── query.html                     # 历史查询页面
├── Dockerfile                         # Docker 多阶段构建
├── go.mod
├── subdomains.txt                     # 默认子域名爆破字典
└── README.md
```

## 技术实现

- **Web 框架**：Gin，提供 RESTful API 和静态页面服务
- **数据库**：SQLite + GORM，存储扫描任务和历史结果
- **并发控制**：全端口使用 Worker Pool + Channel，100 Worker 并行；子域名使用信号量限制 50 并发；CIDR 扫描独立 goroutine
- **CDN 检测**：`DetectCdnByCNAME` 通过 `net.LookupCNAME` 获取域名 CNAME 记录，与 18 家 CDN 特征关键词匹配
- **源站 IP 找回**：`GethostipbyThird` 调 VirusTotal API 获取历史解析 IP → `IsSourceIP` 对候选 IP 发起带 Host 头 + TLS SNI 的 HTTP/HTTPS 请求 → 比较 Title + Favicon MD5 双重验证
- **Banner 抓取**：TCP 连接后 `conn.Read` 读取初始 Banner，`bannerClean` 清洗二进制数据
- **HTTP 探测**：自定义 `DialContext`（TCP 连 IP）+ `ServerName`（TLS SNI 用域名），模拟浏览器请求头（UA/Accept/Accept-Language），正则提取 `<title>`
- **Web 指纹识别**：`Matchfinger` 权重累积引擎 — 铁证(90-100) 单条过，正文(70-85) 基本过，辅助(25-60) 需多信号叠加；支持 header/body/cookie/title/meta 五种位置匹配；`MatchFavicon` 独立 favicon hash 匹配
- **Favicon 识别**：从 HTML 正则提取 `<link icon>` → 相对路径通过 `url.Parse` + `ResolveReference` 正确拼接 → MD5 哈希 → 与 `FaviconDB` 指纹库匹配
- **服务识别**：`BannerIdentify` 三层策略 — Banner 关键词匹配 → 端口查表 `TopPort()` 兜底 → Unknown
- **域名解析**：`ResolveHost` 自动识别 IP/域名，域名调用 `net.LookupHost` 解析
- **子域名爆破**：并发 DNS 解析，50 信号量控制，Mutex 共享结果
- **进度条**：`atomic` 原子计数器 + `\r` 原地刷新

## CDN 检测覆盖

| CDN 厂商          | 检测特征                                                                      |
| ----------------- | ----------------------------------------------------------------------------- |
| Cloudflare        | CNAME 含 `cdn.cloudflare.net`                                                 |
| Akamai            | CNAME 含 `akamaiedge.net` / `akamaized.net` / `edgekey.net` / `edgesuite.net` |
| AWS CloudFront    | CNAME 含 `cloudfront.net`                                                     |
| Fastly            | CNAME 含 `fastly.net`                                                         |
| 阿里云 CDN        | CNAME 含 `kunlun` / `cdngslb.com`                                             |
| 腾讯云 CDN        | CNAME 含 `cdn.dnsv1.com` / `spcdntip.com`                                     |
| 百度云加速        | CNAME 含 `shifen.com` / `jomodns.com`                                         |
| 微软 Azure CDN    | CNAME 含 `azureedge.net`                                                      |
| 华为云 CDN        | CNAME 含 `cdnhwc2.com`                                                        |
| 七牛云            | CNAME 含 `qiniudns.com`                                                       |
| 又拍云            | CNAME 含 `aicdn.com`                                                          |
| 金山云            | CNAME 含 `ksyuncdn.com` / `ks-cdn1.com`                                       |
| 网宿科技          | CNAME 含 `wsdvs.com` / `wsglb0.com` / `wscdns.com`                            |
| 蓝汛 (ChinaCache) | CNAME 含 `ccgslb.com.cn` / `chinacache.net`                                   |
| 白山云            | CNAME 含 `qingcdn.com` / `trpcdn.net` / `bsclink.cn`                          |
| Bilibili CDN      | CNAME 含 `bilicdn`                                                            |
| Incapsula         | CNAME 含 `incapdns.net`                                                       |

## License

MIT

## 安全声明
仅用于授权资产探测和学习研究，禁止用于非法用途。如有违规，请立即停止使用并删除相关数据。
