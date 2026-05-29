package main

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func Top_port() map[int]string {
	//Based in well known ports
	ports := map[int]string{
		1:     "echo",
		9:     "WOL",
		20:    "ftp data",
		21:    "ftp control",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		43:    "whois",
		49:    "TACACS",
		53:    "DNS",
		67:    "BOOTP",
		69:    "TFTP",
		70:    "Gopher",
		71:    "NETRJS",
		80:    "http",
		81:    "TorPark",
		82:    "TorPark",
		88:    "Kerberos",
		110:   "POP3",
		115:   "sFTP",
		143:   "imap",
		220:   "imap3",
		123:   "NTP",
		135:   "RPC",
		443:   "https",
		445:   "Microsoft-ds, Samba",
		465:   "SMTP over TLS",
		514:   "Syslog",
		520:   "RIP",
		521:   "RIPng",
		540:   "UUCP",
		543:   "klogin",
		544:   "kshell",
		587:   "submission",
		993:   "IMAP over TLS",
		995:   "POP3 over TLS",
		1433:  "Microsoft SQL Server",
		3306:  "MySQL",
		3389:  "rdp",
		5432:  "postgres",
		6667:  "irc",
		25565: "minecraft server",
	}
	return ports
}

func Scan_full_port(ip string) []int {
	var jobs = make(chan int, 100)
	var results = make(chan int, 100)
	var wg sync.WaitGroup
	// var ip string
	// fmt.Println("请输入你要探测的ip：")
	// fmt.Scan(&ip)

	//协程开始发任务给jobs
	go func() {
		for port := 1; port <= 65535; port++ {
			jobs <- port
		}
		close(jobs)

	}()

	var scanned int32

	//jobs协程开始接收结果

	workerCount := 100
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go Worker(ip, jobs, results, &wg, &scanned)
	}

	//进度条
	go func() {
		for {
			n := atomic.LoadInt32(&scanned)
			percent := float64(n) / 65535 * 100
			bar := strings.Repeat("=", int(percent/2)) + ">"
			fmt.Printf("\r[%-50s] %.1f%% (%d/65535)", bar, percent, n)
			if n >= 65535 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var openport []int
	for result := range results {
		openport = append(openport, result)
	}

	return openport

}

func Scan_top_ports(ip string) []int {
	topPorts := Top_port()
	var openports []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	for port, _ := range topPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			if IsportAlive(ip, p) {
				mu.Lock()
				openports = append(openports, p)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()

	return openports

}
