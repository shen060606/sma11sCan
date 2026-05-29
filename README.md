# sma11sCan

基于 Go 开发的高并发端口扫描工具。

## 功能

- [x] TCP Connect 端口扫描
- [x] 单 IP 扫描
- [x] CIDR 网段扫描
- [x] Top 常用端口快速扫描（48 个端口）
- [x] 全端口扫描（1-65535）
- [x] 协程并发，Worker Pool 控制并发数
- [x] 进度条显示
- [ ] Banner 抓取
- [ ] HTTP 服务识别
- [ ] CLI 命令行参数

## 快速开始

```bash
# 克隆项目
git clone https://github.com/shen060606/sma11sCan.git
cd sma11sCan

# 运行
go run .
```

## 使用说明

### 单 IP 扫描

```
请输入你要探测的ip：192.168.1.1
请选择扫描模式：
1. top端口扫描
2. 全端口扫描
请输入选择的数字:1
```

### 网段扫描（默认 Top 端口）

```
请输入你要探测的ip：192.168.31.0/24
```

### 扫描模式

| 模式 | 说明 | 端口数 |
|------|------|--------|
| Top 端口 | 常见服务端口（SSH/HTTP/MySQL 等） | 48 |
| 全端口 | 完整 1-65535 | 65535 |

## 项目结构

```
├── main.go          # 入口，菜单与流程控制
├── scanner.go       # 扫描核心（端口探测、Worker Pool、CIDR 解析、输出）
└── scan_modle.go    # 扫描模式（Top端口列表、全端口扫描、快速扫描）
```

## 技术实现

- **并发控制**：全端口扫描使用 Worker Pool + Channel，100 个 Worker 并行
- **快速扫描**：48 个端口直接起 Goroutine + Mutex 共享结果
- **网段扫描**：外层 Goroutine 并发扫每个 IP，内层各自跑扫描模式
- **进度条**：`atomic` 原子计数器 + `\r` 原地刷新

## License

MIT
