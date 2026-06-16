package main

import (
	"fmt"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/shen060606/sma11sCan/global"
	"github.com/shen060606/sma11sCan/internal/cdn"
	"github.com/shen060606/sma11sCan/internal/scanner"
)

type ScanModel struct {
	IP     string `json:"ip" binding:"required"`
	Module string `json:"module"`
	Banner bool   `json:"banner"`
}

func main() {
	// 初始化数据库
	if err := global.InitDB(); err != nil {
		fmt.Println(err)
		return
	}

	gin.SetMode("release")
	r := gin.Default()

	r.LoadHTMLGlob("static/*")

	//接口：get：首页
	r.GET("/", func(c *gin.Context) {
		c.HTML(200, "index.html", nil)
	})

	//接口：post：扫描
	r.POST("/api/v1/scan", func(c *gin.Context) {
		var scanModel ScanModel
		if err := c.ShouldBindJSON(&scanModel); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		fmt.Println(scanModel.IP, scanModel.Module, scanModel.Banner)

		grabbanner := scanModel.Banner
		batchID := global.GenerateBatchID()

		//先看看是不是cidr
		if strings.Contains(scanModel.IP, "/") {
			CIDRmain(scanModel, c, grabbanner, batchID)
		} else {
			//不是cidr，直接扫描
			IPmain(scanModel, c, grabbanner, batchID)
		}
	})

	//接口：get：历史查询页面
	r.GET("/api/v1/scans", func(c *gin.Context) {
		c.HTML(200, "query.html", nil)
	})

	//接口：get：扫描历史列表（按批次分组）
	r.GET("/api/v1/scans/list", func(c *gin.Context) {
		tasks, err := global.GetAllTasks()
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, tasks)
	})

	r.Run(":8088")
}

func CIDRmain(scanmodel ScanModel, c *gin.Context, grabbanner bool, batchID int) {
	scanmodel.Module = "fast"
	type result struct {
		Ip    string               `json:"ip"`
		Ports []scanner.Portresult `json:"ports"`
	}

	var results []result

	ips := scanner.Cidrgetter(scanmodel.IP)

	if len(ips) == 0 {
		c.JSON(400, gin.H{
			"error": "CIDR 格式错误或没有可扫描 IP",
		})
		return
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var gormFail bool
	for _, h := range ips {

		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			ports := scanner.ScanFastPorts(h, h, grabbanner)

			if len(ports) == 0 {
				return
			}

			//放入数据库
			ok := global.IsSaveScanResultSuccess(scanmodel.IP, h, scanmodel.Module, batchID, false, "", ports)

			mu.Lock()
			results = append(results, result{h, ports})
			mu.Unlock()

			if !ok {
				gormFail = true
				return
			}
		}(h)

	}
	wg.Wait()

	if gormFail {
		c.JSON(500, gin.H{
			"message": "保存数据库失败!!!",
		})
		return
	}
	var aliveCount int
	for _, r := range results {
		if len(r.Ports) > 0 {
			scanner.PrintResult(r.Ip, r.Ports)
			aliveCount++
		}
	}

	if aliveCount == 0 {
		fmt.Println("没有存活的端口")
		c.JSON(200, gin.H{
			"message": "没有存活的端口",
		})
	} else {
		c.JSON(200, gin.H{
			"result": results,
		})

	}
}

func IPmain(scanmodel ScanModel, c *gin.Context, grabbanner bool, batchID int) {
	//不是cidr，直接扫描
	host := scanmodel.IP
	cdninfo := cdn.DetectCdnByCNAME(host)

	if cdninfo.Iscdn {
		fmt.Println("[CDN] true")
		fmt.Println("[CDN Provider]", strings.Join(cdninfo.Providers, ","))
	}
	ip := scanner.ResolveHost(scanmodel.IP)
	if ip == "" {
		fmt.Println("无法解析目标域名!!!")
		c.JSON(400, gin.H{"error": "无法解析目标域名"})
		return
	}

	var gormFail bool

	var Alive_ports []scanner.Portresult
	switch scanmodel.Module {
	case "fast":
		Alive_ports = scanner.ScanFastPorts(ip, host, grabbanner)
		gormFail = !global.IsSaveScanResultSuccess(host, ip, scanmodel.Module, batchID, cdninfo.Iscdn, strings.Join(cdninfo.Providers, ","), Alive_ports)

	case "full":
		Alive_ports = scanner.ScanFullPort(ip, host, grabbanner)
		gormFail = !global.IsSaveScanResultSuccess(host, ip, scanmodel.Module, batchID, cdninfo.Iscdn, strings.Join(cdninfo.Providers, ","), Alive_ports)

	case "top":
		Alive_ports = scanner.ScanTopPorts(ip, host, grabbanner)
		gormFail = !global.IsSaveScanResultSuccess(host, ip, scanmodel.Module, batchID, cdninfo.Iscdn, strings.Join(cdninfo.Providers, ","), Alive_ports)
	}

	if gormFail {
		c.JSON(500, gin.H{
			"message": "保存数据库失败!!!",
		})
		return
	}

	if len(Alive_ports) == 0 {
		c.JSON(200, gin.H{
			"ip":      ip,
			"cdn":     cdninfo.Providers,
			"message": "没有存活的端口",
		})

		scanner.PrintResult(ip, Alive_ports)

	} else {
		c.JSON(200, gin.H{
			"ip":    ip,
			"cdn":   cdninfo.Providers,
			"ports": Alive_ports,
		})

		scanner.PrintResult(ip, Alive_ports)

	}
}
