package global

import (
	"fmt"

	"github.com/shen060606/sma11sCan/internal/scanner"
)

// 保存扫描结果到数据库
func SaveScanResult(target, ip, module, cdn string, batchid int, iscdn bool, ports []scanner.Portresult) error {
	task := ScanTask{
		Target:  target,
		BatchID: batchid,
		IP:      ip,
		Module:  module,
		IsCDN:   iscdn,
		CDN:     cdn,
	}

	for _, p := range ports {
		task.Results = append(task.Results, ScanResult{
			IP:           ip,
			Port:         p.Port,
			Server:       p.Server,
			Banner:       p.Banner,
			Fingerprints: p.Fingerprints,
		})
	}

	return DB.Create(&task).Error
}

// 主函数调用看是否成功保存
func IsSaveScanResultSuccess(target, ip, module string, batchid int, iscdn bool, cdn string, ports []scanner.Portresult) bool {
	err := SaveScanResult(target, ip, module, cdn, batchid, iscdn, ports)
	if err != nil {
		fmt.Println("保存扫描结果到数据库失败:", err)
		return false
	}
	return true
}
