// dns，cname，检测
package main

import (
	"net"
	"strings"
)

type Cdnrule struct {
	Provider      string
	Cnamekeywords []string
}

type Cdnresult struct {
	Iscdn     bool
	Providers []string
	// Cnames    []string
	// Evidences []string
	Hostip string
}

// CDN规则列表，CNAME包含数组任意关键词即判定使用CDN
var CdnList = []Cdnrule{
	// 国内主流CDN
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

// 查询子域名的ip来看也没有源站ip
func DetectCdnByDNS(domain string, wordlist string, ip string) Cdnresult {
	var finalresult Cdnresult
	//拿爆破字典
	words := ReadWordlist(wordlist)

	cname, err := net.LookupCNAME(domain)
	if err != nil {
		// return Cdnresult{Iscdn: false, Providers: []string{}, Cnames: []string{}, Evidences: []string{}}
		return Cdnresult{Iscdn: false, Providers: []string{}}
	}

	//判断cname是否包含关键词
	cname = strings.ToLower(cname)
	for _, rule := range CdnList {
		for _, keyword := range rule.Cnamekeywords {
			if strings.Contains(cname, strings.ToLower(keyword)) {
				finalresult.Iscdn = true
				finalresult.Providers = append(finalresult.Providers, rule.Provider)
			}
		}
	}

	if !finalresult.Iscdn {
		return finalresult
	}

	hosts := GetdomainsForce(domain, words)

	var results = make(map[string]int)
	for _, host := range hosts {
		ips, err := net.LookupHost(host)
		if err != nil {
			continue
		}
		for _, domainip := range ips {
			results[domainip]++
		}
	}

	delete(results, ip)

	var max int
	var hostip string
	for ip, count := range results {
		if count > max {
			max = count
			hostip = ip
		}
	}
	finalresult.Hostip = hostip

	return finalresult
}
