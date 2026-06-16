package global

import "time"

//扫描的配置
type ScanTask struct {
	ID        uint
	BatchID   int    // 一次 API 请求/一次 CLI 执行的批次 ID
	Target    string //原始输入
	IP        string //解析后的IP
	Module    string
	IsCDN     bool
	CDN       string
	CreatedAt time.Time
	Results   []ScanResult
}

//扫描结果
type ScanResult struct {
	ID           uint
	ScanTaskID   uint
	IP           string
	Port         int
	Server       string
	Banner       string
	Fingerprints string
	CreatedAt    time.Time
}
