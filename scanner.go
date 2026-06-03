package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Portresult struct {
	Port         int
	Banner       string
	Server       string
	Fingerprints string
}

func IsportAlive(ip string, port int) bool {
	ip_port := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", ip_port, 200*time.Millisecond)

	if err != nil {
		//fmt.Println(err)
		return false
	}

	defer conn.Close()
	return true
}

func Worker(ip string, jobs <-chan int, results chan<- Portresult, wg *sync.WaitGroup, scanned *int32, grabbanner bool) {
	defer wg.Done()
	for port := range jobs {
		if IsportAlive(ip, port) {
			var banner string
			var server string
			var info *HttpInfo
			var err error
			if grabbanner {
				if port == 80 || port == 443 || port == 8080 || port == 3128 || port == 8081 || port == 9090 {
					info, err = Httpbannerget(ip, port)
					if err != nil {
						fmt.Println(err)
						banner = ""
					} else {
						banner = info.Display()
					}

				} else {
					banner = Bannerget(ip, port)
				}
				server = BannerIdentify(port, banner)
			}
			if info != nil {
				results <- Portresult{Port: port, Banner: banner, Server: server, Fingerprints: info.Fingerprints}
			} else {
				results <- Portresult{Port: port, Banner: banner, Server: server}
			}
		}
		atomic.AddInt32(scanned, 1)
	}

}

// 将网段转化成所有ip
func Cidrgetter(cidr string) []string {
	var hosts []string
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Println(err)
		fmt.Println("CIDR格式不正确或输入错误")
		return nil
	}
	//binary.BigEndian.Uint32()将ip地址转化成32位无符号整数
	//eg:255.255.255.0 -> 0xFFFFFF00
	ip_firstaddr := binary.BigEndian.Uint32(ipnet.IP)        //网络地址（子网第一个地址）
	ip_maskaddr := binary.BigEndian.Uint32(ipnet.Mask)       //子网掩码
	ip_lastaddr := ip_firstaddr | (ip_maskaddr ^ 0xFFFFFFFF) //广播地址（子网最后一个地址）

	for i := ip_firstaddr + 1; i < ip_lastaddr; i++ {
		ip_addr := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip_addr, i)
		hosts = append(hosts, ip_addr.String())
	}
	return hosts
}

func PrintResult(ip string, results []Portresult) {
	if len(results) == 0 {
		fmt.Println("没有存活的端口")
		return
	}

	fmt.Println("存活的端口：")
	for _, p := range results {
		// 拼输出行
		line := fmt.Sprintf("%s:%-6d", ip, p.Port)

		if p.Server != "" {
			line += fmt.Sprintf(" [%-8s]", p.Server)
		}
		if p.Fingerprints != "" {
			line += fmt.Sprintf(" <%s>", p.Fingerprints)
		}
		if p.Banner != "" {
			line += " " + p.Banner
		}
		fmt.Println(line)
	}
}

// 解析域名
func ResolveHost(ip string) string {
	if net.ParseIP(ip) != nil {
		return ip
	}

	addrip, err := net.LookupHost(ip) //返回的是字符串数组[0]是ipv4地址,[1]是ipv6地址
	if err != nil {
		return ""
	}
	return addrip[0]
}
