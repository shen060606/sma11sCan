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
	var domain string
	var noscan bool
	var wordlist string

	// fmt.Println("请输入你要探测的ip：")
	//fmt.Scan(&ip)
	flag.StringVar(&ip, "ip", "", "目标域名/ip/CIDR网段")
	flag.StringVar(&module, "module", "fast", "扫描模式 (fast 或 top 或 full)")
	flag.BoolVar(&grabbanner, "banner", false, "抓取banner服务")
	flag.StringVar(&domain, "domain", "", "目标域名(收集子域名)")
	flag.BoolVar(&noscan, "noscan", false, "只收集子域名，不进行端口扫描")
	flag.StringVar(&wordlist, "wordlist", "subdomains.txt", "子域名收集时的字典文件")

	flag.Parse()

	//子域名模式
	if domain != "" {
		//subdomains := GetSubdomains(domain)
		words := ReadWordlist(wordlist)
		if len(words) == 0 {
			fmt.Println("字典文件不存在")
			return
		}
		subdomains := GetdomainsForce(domain, words)
		if len(subdomains) == 0 {
			fmt.Println("没有子域名")
			return
		}

		fmt.Printf("收集到%d个子域名：\n", len(subdomains))

		for _, sub := range subdomains {
			fmt.Println(" ", sub)
		}

		if noscan {
			return
		}

		//带其他参数时，每个 IP 记住对应的子域名
		ipToHost := make(map[string]string)
		for _, sub := range subdomains {
			if ip := ResolveHost(sub); ip != "" {
				if _, exists := ipToHost[ip]; !exists {
					ipToHost[ip] = sub
				}
			}
		}

		fmt.Printf("\n解析到%d个IP地址，开始扫描...\n", len(ipToHost))

		for ipstr, host := range ipToHost {
			PrintResult(ipstr, Scan_fast_ports(ipstr, host, grabbanner))
		}
		return
	}

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
				ports := Scan_fast_ports(h, h, grabbanner)
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
						fmt.Printf("%s:%d  %s %s\n", r.ip, p.Port, p.Server, p.Banner)
					} else if p.Server != "" {
						fmt.Printf("%s:%d  %s\n", r.ip, p.Port, p.Server)
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
		host := ip // 保存原始输入（域名或IP）
		ip = ResolveHost(ip)
		if ip == "" {
			fmt.Println("无法解析目标域名!!!")
			return
		}

		var Alive_ports []Portresult
		switch module {
		case "fast":
			Alive_ports = Scan_fast_ports(ip, host, grabbanner)

		case "full":
			Alive_ports = Scan_full_port(ip, host, grabbanner)

		case "top":
			Alive_ports = Scan_top_ports(ip, host, grabbanner)

		default:
			fmt.Println("无效的扫描模式")
		}
		PrintResult(ip, Alive_ports)
	}
}
