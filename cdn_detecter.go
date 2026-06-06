// dns，cname，检测
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

type Cdnrule struct {
	Provider      string
	Cnamekeywords []string
}

type Cdninfo struct {
	Iscdn     bool
	Providers []string
}

var Cdnrealip string

// 用于可能是源站域名的ip地址
type OriginCandiate struct {
	Ip     string
	Source string
	Date   int64
}

// CDN规则列表，CNAME包含数组任意关键词即判定使用CDN
var CdnList = []Cdnrule{
	// 国内主流CDN
	{Provider: "Bilibili CDN", Cnamekeywords: []string{"bilicdn"}},
	{Provider: "百度系CDN/调度", Cnamekeywords: []string{"shifen.com"}},
	{Provider: "阿里云CDN", Cnamekeywords: []string{"kunlun", "cdngslb.com", "inittt.com"}},
	{Provider: "腾讯云CDN", Cnamekeywords: []string{"cdn.dnsv1.com", "ecdn.dnsv1.com", "tc.cdntip.com", "spcdntip.com"}},
	{Provider: "百度智能云", Cnamekeywords: []string{"jomodns.com"}},
	{Provider: "华为云CDN", Cnamekeywords: []string{"cdnhwc2.com"}},
	{Provider: "七牛云", Cnamekeywords: []string{"qiniudns.com"}},
	{Provider: "又拍云", Cnamekeywords: []string{"aicdn.com"}},
	{Provider: "金山云", Cnamekeywords: []string{"ksyuncdn.com", "ks-cdn1.com"}},
	{Provider: "网宿科技", Cnamekeywords: []string{"wsdvs.com", "wsglb0.com", "wscdns.com"}},
	{Provider: "蓝汛(ChinaCache)", Cnamekeywords: []string{"ccgslb.com.cn", "chinacache.net"}},
	{Provider: "白山云", Cnamekeywords: []string{"qingcdn.com", "trpcdn.net", "bsclink.cn"}},

	// 国外主流CDN
	{Provider: "Cloudflare", Cnamekeywords: []string{"cdn.cloudflare.net"}},
	{Provider: "Akamai", Cnamekeywords: []string{"akamaiedge.net", "akamaized.net", "edgekey.net", "edgesuite.net"}},
	{Provider: "AWS CloudFront", Cnamekeywords: []string{"cloudfront.net"}},
	{Provider: "Fastly", Cnamekeywords: []string{"fastly.net", "map.fastly.net"}},
	{Provider: "微软AzureCDN", Cnamekeywords: []string{"azureedge.net"}},
	{Provider: "Incapsula", Cnamekeywords: []string{"incapdns.net"}},
}

// 通过 CNAME 记录判断目标是否使用 CDN
func DetectCdnByCNAME(domain string) Cdninfo {
	var finalresult Cdninfo

	cname, err := net.LookupCNAME(domain)
	if err != nil {
		// return Cdnresult{Iscdn: false, Providers: []string{}, Cnames: []string{}, Evidences: []string{}}
		return Cdninfo{Iscdn: false, Providers: []string{}}
	}

	//判断cname是否包含关键词
	cname = strings.ToLower(cname)
	for _, rule := range CdnList {
		for _, keyword := range rule.Cnamekeywords {
			if strings.Contains(cname, strings.ToLower(keyword)) {
				finalresult.Iscdn = true
				finalresult.Providers = append(finalresult.Providers, rule.Provider)
				break
			}
		}
	}
	fmt.Println("[CNAME]", cname)
	return finalresult

}

//内部查找源站ip，准确率太低了
// func FindHostip(domain string, ip string, wordlist string) string {
// 	cdninfo := DetectCdnByCNAME(domain)

// 	if cdninfo.Iscdn == false {
// 		return ip
// 	}

// 	//拿爆破字典
// 	words := ReadWordlist(wordlist)
// 	hosts := GetdomainsForce(domain, words)

// 	var results = make(map[string]int)
// 	for _, host := range hosts {
// 		ips, err := net.LookupHost(host)
// 		if err != nil {
// 			continue
// 		}
// 		for _, domainip := range ips {
// 			results[domainip]++
// 		}
// 	}

// 	delete(results, ip)

// 	var max int
// 	var hostip string
// 	for ip, count := range results {
// 		if count > max {
// 			max = count
// 			hostip = ip
// 		}
// 	}

// 	return hostip

// }

// 获取可能源站ip
func FindallHostip(domain string) []OriginCandiate {
	var candidates []OriginCandiate

	candidates = append(candidates, GethostipbyThird(domain)...)

	return candidates
}

// 利用第三方来获取源站ip
func GethostipbyThird(domain string) []OriginCandiate {
	apikey := os.Getenv("VT_API_KEY")
	if apikey == "" {
		return nil
	}

	url := "https://www.virustotal.com/api/v3/domains/" + domain + "/resolutions"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("x-apikey", apikey)

	client := http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)

	if err != nil {
		return nil
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var data struct {
		Data []struct {
			Attributes struct {
				IPAddress string `json:"ip_address"`
				Date      int64  `json:"date"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	var results []OriginCandiate

	for _, item := range data.Data {
		ip := item.Attributes.IPAddress
		if ip == "" {
			continue
		}

		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		results = append(results, OriginCandiate{Ip: ip, Source: "VirusTotal", Date: item.Attributes.Date})
	}

	return results
}

// 判断候选 IP 是否是源站 IP：请求原域名和候选 IP，比较 title + favicon 哈希
// 候选 IP 请求时带原域名 Host 头（解决基于 Host 区分的虚拟主机问题）
func IsSourceIP(domain string, candidates []OriginCandiate) string {
	// 先获取原域名的 title 和 favicon
	title1, iconhashes1 := GetResponse(domain)

	for _, candidate := range candidates {
		ip := candidate.Ip
		// 请求候选 IP 时设置 Host 头为原域名，模拟真实访问
		title, iconhashes := GetResponseWithHost(ip, domain)

		if (title != "" && title1 != "" &&
			strings.TrimSpace(title) == strings.TrimSpace(title1)) ||
			HasSameHash(iconhashes, iconhashes1) {
			return ip
		}
	}
	return ""
}

// GetResponse 获取目标的 title 和 favicon 哈希，自动尝试 HTTP 和 HTTPS
func GetResponse(target string) (string, []string) {
	urls := buildURLs(target)
	for _, u := range urls {
		title, hashes, ok := GetResponseByURL(u, "")
		if ok {
			return title, hashes
		}
	}
	return "", nil
}

// GetResponseWithHost 请求目标 URL/IP，但 Host 头和 TLS SNI 设为指定域名（用于验证源站 IP）
func GetResponseWithHost(target string, host string) (string, []string) {
	urls := buildURLs(target)
	for _, u := range urls {
		title, hashes, ok := GetResponseByURL(u, host)
		if ok {
			return title, hashes
		}
	}
	return "", nil
}

// buildURLs 将目标转换为带协议的 URL 列表，自动补全 http:// 和 https://
func buildURLs(target string) []string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return []string{target}
	}
	return []string{"http://" + target, "https://" + target}
}

// GetResponseByURL 执行一次 HTTP 请求，返回 title、favicon 哈希和是否成功
// hostOverride 非空时覆盖 Host 头并设置 TLS SNI（用于候选 IP 验证源站）
func GetResponseByURL(targetURL string, hostOverride string) (string, []string, bool) {
	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	// HTTPS 请求候选 IP 时，SNI 设为原域名，否则服务器可能返回错误证书/默认站点
	if hostOverride != "" && strings.HasPrefix(targetURL, "https://") {
		tlsConfig.ServerName = hostOverride
	}

	client := http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return "", nil, false
	}

	// 设置 Host 头为原域名，解决基于 Host 的虚拟主机区分问题
	if hostOverride != "" {
		req.Host = hostOverride
	}

	req.Header.Set("User-Agent",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36")
	req.Header.Set("Accept",
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	req.Header.Set("Connection", "close")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, err := client.Do(req)
	if err != nil {
		return "", nil, false
	}
	defer resp.Body.Close()

	var title string
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	match := re.FindStringSubmatch(string(body))
	if len(match) > 1 {
		title = match[1]
	}

	// 传入完整 URL（带协议），解决 favicon 相对路径拼接问题
	iconhashes := GetFavicon(targetURL, string(body))
	return title, iconhashes, true
}

// 帮助判断icon值是否有相同的
func HasSameHash(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}

	seen := make(map[string]struct{})

	for _, hash := range a {
		if hash == "" {
			continue
		}
		seen[hash] = struct{}{}
	}

	for _, hash := range b {
		if hash == "" {
			continue
		}

		if _, ok := seen[hash]; ok {
			return true
		}
	}

	return false
}
