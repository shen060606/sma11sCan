package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

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

func Worker(ip string, jobs <-chan int, results chan<- int, wg *sync.WaitGroup, scanned *int32) {
	defer wg.Done()
	for port := range jobs {
		if IsportAlive(ip, port) {
			results <- port
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

func PrintResult(ip string, ports []int) {
	if len(ports) == 0 {
		fmt.Println("没有存活的端口")
	} else {
		fmt.Println("存活的端口：")
		for _, p := range ports {
			fmt.Printf("%s:%d\n", ip, p)
		}
	}
}
