package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shen060606/sma11sCan/internal/banner"
)

type Portresult struct {
	Port         int
	Banner       string
	Server       string
	Fingerprints string
}

func IsportAlive(ip string, port int) bool {
	ip_port := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", ip_port, 500*time.Millisecond)

	if err != nil {
		return false
	}

	defer conn.Close()
	return true
}

func worker(ip string, host string, jobs <-chan int, results chan<- Portresult, wg *sync.WaitGroup, scanned *int32, grabbanner bool) {
	defer wg.Done()
	for port := range jobs {
		if IsportAlive(ip, port) {
			var bann string
			var server string
			var info *banner.HttpInfo
			var err error
			if grabbanner {
				if port == 80 || port == 443 || port == 8080 || port == 3128 || port == 8081 || port == 9090 {
					info, err = banner.Httpbannerget(ip, port, host)
					if err != nil {
						fmt.Println(err)
						bann = ""
					} else {
						bann = info.Display()
					}

				} else {
					bann = banner.Bannerget(ip, port)
				}
				server = BannerIdentify(port, bann)
			}
			if info != nil {
				results <- Portresult{Port: port, Banner: bann, Server: server, Fingerprints: info.Fingerprints}
			} else {
				results <- Portresult{Port: port, Banner: bann, Server: server}
			}
		}
		atomic.AddInt32(scanned, 1)
	}
}

// Cidrgetter 将网段转化成所有ip
func Cidrgetter(cidr string) []string {
	var hosts []string
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Println(err)
		fmt.Println("CIDR格式不正确或输入错误")
		return nil
	}
	ip_firstaddr := binary.BigEndian.Uint32(ipnet.IP)
	ip_maskaddr := binary.BigEndian.Uint32(ipnet.Mask)
	ip_lastaddr := ip_firstaddr | (ip_maskaddr ^ 0xFFFFFFFF)

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

// ResolveHost 解析域名
func ResolveHost(ip string) string {
	if net.ParseIP(ip) != nil {
		return ip
	}

	addrip, err := net.LookupHost(ip)
	if err != nil {
		return ""
	}
	return addrip[0]
}
