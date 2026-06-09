package main

import (
	"flag"
	"fmt"
	"strings"
	"sync"

	"github.com/shen060606/sma11sCan/internal/cdn"
	"github.com/shen060606/sma11sCan/internal/scanner"
	"github.com/shen060606/sma11sCan/internal/subdomain"
)

func main() {
	var module string
	var ip string
	var grabbanner bool
	var domain string
	var noscan bool
	var wordlist string

	flag.StringVar(&ip, "ip", "", "目标域名/ip/CIDR网段")
	flag.StringVar(&module, "module", "fast", "扫描模式 (fast 或 top 或 full)")
	flag.BoolVar(&grabbanner, "banner", false, "抓取banner服务")
	flag.StringVar(&domain, "domain", "", "目标域名(收集子域名)")
	flag.BoolVar(&noscan, "noscan", false, "只收集子域名，不进行端口扫描")
	flag.StringVar(&wordlist, "wordlist", "subdomains.txt", "子域名收集时的字典文件")

	flag.Parse()

	//子域名模式
	if domain != "" {
		words := subdomain.ReadWordlist(wordlist)
		if len(words) == 0 {
			fmt.Println("字典文件不存在")
			return
		}
		subdomains := subdomain.GetdomainsForce(domain, words)
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
			if ip := scanner.ResolveHost(sub); ip != "" {
				if _, exists := ipToHost[ip]; !exists {
					ipToHost[ip] = sub
				}
			}
		}

		fmt.Printf("\n解析到%d个IP地址，开始扫描...\n", len(ipToHost))

		for ipstr, host := range ipToHost {
			scanner.PrintResult(ipstr, scanner.ScanFastPorts(ipstr, host, grabbanner))
		}
		return
	}

	if strings.Contains(ip, "/") {

		//为了ip和端口对应输出，设置一个结构体
		type result struct {
			ip    string
			ports []scanner.Portresult
		}
		var results []result

		ips := scanner.Cidrgetter(ip)
		if len(ips) == 0 {
			return
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		for _, h := range ips {

			wg.Add(1)
			go func(h string) {
				defer wg.Done()
				ports := scanner.ScanFastPorts(h, h, grabbanner)
				mu.Lock()
				results = append(results, result{h, ports})
				mu.Unlock()
			}(h)

		}
		wg.Wait()

		var aliveCount int
		for _, r := range results {
			if len(r.ports) > 0 {
				scanner.PrintResult(r.ip, r.ports)
				aliveCount++
			}
		}
		if aliveCount == 0 {
			fmt.Println("没有存活的端口")
		}

	} else {
		host := ip // 保存原始输入（域名或IP）
		ip = scanner.ResolveHost(ip)
		if ip == "" {
			fmt.Println("无法解析目标域名!!!")
			return
		}

		// 进行 CDN 检测，尝试找到源站 IP
		cdninfo := cdn.DetectCdnByCNAME(host)

		if cdninfo.Iscdn {
			fmt.Println("[CDN] true")
			fmt.Println("[CDN Provider]", strings.Join(cdninfo.Providers, ","))

			candidates := cdn.FindallHostip(host)
			if len(candidates) > 0 {
				fmt.Printf("[VirusTotal] 获取到 %d 个候选 IP\n", len(candidates))
				for _, c := range candidates {
					fmt.Printf("    %-15s  source=%s  date=%d\n", c.Ip, c.Source, c.Date)
				}

				// 用 title + favicon 对比，验证哪个候选 IP 是源站
				realIP := cdn.IsSourceIP(host, candidates)
				if realIP != "" {
					cdn.Cdnrealip = realIP
					fmt.Println("[Origin IP]", realIP)
					// 找到源站 IP 后，用真实 IP 继续扫描
					ip = realIP
				} else {
					fmt.Println("[Origin IP] 未能验证源站 IP，仍使用 CDN 节点扫描")
				}
			} else {
				fmt.Println("[VirusTotal] 无候选 IP（需设置 VT_API_KEY 环境变量）")
			}
		}

		var Alive_ports []scanner.Portresult
		switch module {
		case "fast":
			Alive_ports = scanner.ScanFastPorts(ip, host, grabbanner)

		case "full":
			Alive_ports = scanner.ScanFullPort(ip, host, grabbanner)

		case "top":
			Alive_ports = scanner.ScanTopPorts(ip, host, grabbanner)

		default:
			fmt.Println("无效的扫描模式")
		}
		scanner.PrintResult(ip, Alive_ports)
	}
}
