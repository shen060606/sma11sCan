package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Crtresult struct {
	Namevalue string `json:"name_value"`
}

// 获取子域名，第三方的，这个crt.sh老是链接失败，所以用下面的爆破子域名的
func GetSubdomains(domain string) []string {
	//先去除前缀留下主域名
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "www.")

	client := &http.Client{Timeout: 15 * time.Second}

	resp, err := client.Get("https://crt.sh/?q=%25." + domain + "&output=json")
	if err != nil {
		fmt.Println("[!] crt.sh 请求失败:", err)
		return nil
	}

	defer resp.Body.Close()

	// 检查 HTTP 状态码
	if resp.StatusCode != 200 {
		fmt.Printf("[!] crt.sh 返回异常状态码: %d %s\n", resp.StatusCode, resp.Status)
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	var results []Crtresult
	json.Unmarshal(body, &results)

	seen := make(map[string]bool) //创建去重表
	var subs []string
	for _, item := range results {
		//去除换行符
		for _, name := range strings.Split(item.Namevalue, "\n") {
			name = strings.TrimSpace(name) //去除头和尾的空白
			if strings.Contains(name, domain) && !strings.HasPrefix(name, "*") {
				if !seen[name] {
					seen[name] = true
					subs = append(subs, name)
				}
			}

		}
	}
	return subs

}

// brute force子域名爆破
func GetdomainsForce(domain string, wordlist []string) []string {

	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "www.")

	var subs []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50) //设置并发数

	for _, word := range wordlist {
		wg.Add(1)
		go func(w string) {
			defer wg.Done()
			sem <- struct{}{} //获取信号量
			defer func() { <-sem }()

			sub := w + "." + domain
			if ip := ResolveHost(sub); ip != "" {
				mu.Lock()
				subs = append(subs, sub)
				mu.Unlock()
			}
		}(word)

	}
	wg.Wait()
	return subs

}

func ReadWordlist(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	lines := strings.Split(string(data), "\n")

	var words []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			words = append(words, line)

		}
	}
	return words
}
