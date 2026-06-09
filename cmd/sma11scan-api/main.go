package main

import (
	"fmt"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/shen060606/sma11sCan/internal/cdn"
	"github.com/shen060606/sma11sCan/internal/scanner"
)

type ScanModel struct {
	IP     string `json:"ip" binding:"required"`
	Module string `json:"module"`
	Banner bool   `json:"banner"`
}

func main() {
	gin.SetMode("release")
	r := gin.Default()

	r.LoadHTMLGlob("./../../static/*")

	r.GET("/", func(c *gin.Context) {
		c.HTML(200, "index.html", nil)
	})

	r.POST("/api/v1/scan", func(c *gin.Context) {
		var scanModel ScanModel
		if err := c.ShouldBindJSON(&scanModel); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		fmt.Println(scanModel.IP, scanModel.Module, scanModel.Banner)

		grabbanner := scanModel.Banner

		//先看看是不是cidr
		if strings.Contains(scanModel.IP, "/") {
			//
			CIDRmain(scanModel, c, grabbanner)

		} else {
			//不是cidr，直接扫描
			IPmain(scanModel, c, grabbanner)

		}

	})

	r.Run(":8088")
}

func CIDRmain(scanmodel ScanModel, c *gin.Context, grabbanner bool) {
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
	for _, h := range ips {

		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			ports := scanner.ScanFastPorts(h, h, grabbanner)

			if len(ports) == 0 {
				return
			}
			mu.Lock()
			results = append(results, result{h, ports})
			mu.Unlock()
		}(h)

	}
	wg.Wait()

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

func IPmain(scanmodel ScanModel, c *gin.Context, grabbanner bool) {
	//不是cidr，直接扫描
	host := scanmodel.IP
	cdninfo := cdn.DetectCdnByCNAME(host)

	if cdninfo.Iscdn {
		fmt.Println("[CDN] true")
		fmt.Println("[CDN Provider]", strings.Join(cdninfo.Providers, ","))
		// c.JSON(200, gin.H{
		// 	"message": cdninfo.Providers,
		// })
	}
	ip := scanner.ResolveHost(scanmodel.IP)
	if ip == "" {
		fmt.Println("无法解析目标域名!!!")
		c.JSON(400, gin.H{"error": "无法解析目标域名"})
		return
	}

	var Alive_ports []scanner.Portresult
	switch scanmodel.Module {
	case "fast":
		Alive_ports = scanner.ScanFastPorts(ip, host, grabbanner)

	case "full":
		Alive_ports = scanner.ScanFullPort(ip, host, grabbanner)

	case "top":
		Alive_ports = scanner.ScanTopPorts(ip, host, grabbanner)

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
