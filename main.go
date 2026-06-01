package main

import (
	"flag"
	"fmt"
	"strings"
	"sync"
)

func main() {
	var module string
	var ip string
	var grabbanner bool
	// fmt.Println("请输入你要探测的ip：")
	//fmt.Scan(&ip)
	flag.StringVar(&ip, "ip", "", "目标ip/CIDR网段")
	flag.StringVar(&module, "module", "top", "扫描模式 (top 或 full)")
	flag.BoolVar(&grabbanner, "banner", false, "抓取banner服务")

	flag.Parse()

	if strings.Contains(ip, "/") {

		//为了ip和端口对应输出，设置一个结构体
		type result struct {
			ip    string
			ports []Portresult
		}
		var results []result

		ips := Cidrgetter(ip)
		if len(ips) == 0 {
			return
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		for _, h := range ips {

			wg.Add(1)
			go func(h string) {
				defer wg.Done()
				ports := Scan_top_ports(h, grabbanner)
				mu.Lock()
				results = append(results, result{h, ports})
				mu.Unlock()
			}(h)

		}
		wg.Wait()

		if len(results) == 0 {
			fmt.Println("没有存活的端口")
		} else {
			fmt.Println("存活的端口如下：")
			for _, r := range results {
				for _, p := range r.ports {
					if p.Banner != "" {
						fmt.Printf("%s:%d  %s\n", r.ip, p.Port, p.Banner)
					} else {
						fmt.Printf("%s:%d\n", r.ip, p.Port)
					}
				}
			}
		}
	} else {
		// fmt.Println("请选择扫描模式：")
		// fmt.Println("1. top端口扫描")
		// fmt.Println("2. 全端口扫描")

		// fmt.Println("请输入选择的数字:")

		var Alive_ports []Portresult
		switch module {
		case "top":
			Alive_ports = Scan_top_ports(ip, grabbanner)

		case "full":
			Alive_ports = Scan_full_port(ip, grabbanner)

		default:
			fmt.Println("无效的扫描模式")
		}
		PrintResult(ip, Alive_ports)
	}
}
