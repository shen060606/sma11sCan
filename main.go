package main

import (
	"fmt"
	"strings"
	"sync"
)

func main() {

	var ip string
	fmt.Println("请输入你要探测的ip：")
	fmt.Scan(&ip)

	// fmt.Println("请选择扫描模式：")
	// fmt.Println("1. top端口扫描")
	// fmt.Println("2. 全端口扫描")

	// var mode int
	// fmt.Println("请输入选择的数字:")
	// fmt.Scan(&mode)

	if strings.Contains(ip, "/") {

		//为了ip和端口对应输出，设置一个结构体
		type result struct {
			ip    string
			ports []int
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
				ports := Scan_top_ports(h)
				mu.Lock()
				results = append(results, result{h, ports})
				mu.Unlock()
			}(h)

		}
		wg.Wait()

		if len(results) == 0 {
			fmt.Println("没有存活的端口")
		} else {
			for _, r := range results {
				for _, p := range r.ports {
					fmt.Printf("%s:%d\n", r.ip, p)
				}
			}
		}
	} else {
		fmt.Println("请选择扫描模式：")
		fmt.Println("1. top端口扫描")
		fmt.Println("2. 全端口扫描")

		var mode int
		fmt.Println("请输入选择的数字:")
		fmt.Scan(&mode)

		var Alive_ports []int
		switch mode {
		case 1:
			Alive_ports = Scan_top_ports(ip)

		case 2:
			Alive_ports = Scan_full_port(ip)
		}
		PrintResult(ip, Alive_ports)
	}
}
