package subdomain

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/shen060606/sma11sCan/internal/scanner"
)

type crtresult struct {
	Namevalue string `json:"name_value"`
}

// GetSubdomains 通过crt.sh获取子域名
func GetSubdomains(domain string) []string {
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

	if resp.StatusCode != 200 {
		fmt.Printf("[!] crt.sh 返回异常状态码: %d %s\n", resp.StatusCode, resp.Status)
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	var results []crtresult
	json.Unmarshal(body, &results)

	seen := make(map[string]bool)
	var subs []string
	for _, item := range results {
		for _, name := range strings.Split(item.Namevalue, "\n") {
			name = strings.TrimSpace(name)
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

// GetdomainsForce 暴力枚举子域名
func GetdomainsForce(domain string, wordlist []string) []string {

	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "www.")

	var subs []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)

	for _, word := range wordlist {
		wg.Add(1)
		go func(w string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			sub := w + "." + domain
			if ip := scanner.ResolveHost(sub); ip != "" {
				mu.Lock()
				subs = append(subs, sub)
				mu.Unlock()
			}
		}(word)
	}
	wg.Wait()
	return subs
}

// ReadWordlist 读取子域名字典文件
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
