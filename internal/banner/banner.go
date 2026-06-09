package banner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/shen060606/sma11sCan/internal/fingerprint"
)

// Bannerget TCP端口Banner抓取
func Bannerget(ip string, port int) string {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)

	if err != nil {
		return ""
	}

	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	buf := make([]byte, 1024)

	n, err := conn.Read(buf)

	if err != nil {
		return ""
	}

	result := strings.TrimSpace(string(buf[:n]))
	return bannerClean(result)
}

type HttpInfo struct {
	Status       string
	Title        string
	Headers      string
	Body         string
	Server       string
	Fingerprints string
}

// Httpbannerget 80,443,8080端口http请求
func Httpbannerget(ip string, port int, host string) (*HttpInfo, error) {

	info, err := dorequest("https", ip, port, host)
	if err == nil {
		return info, nil
	}

	return dorequest("http", ip, port, host)
}

// ip: TCP 连接目标 IP；host: SNI + Host 头使用的域名（没域名时等于 ip）
func dorequest(scheme string, ip string, port int, host string) (*HttpInfo, error) {
	var headers strings.Builder

	dialer := &net.Dialer{Timeout: 2 * time.Second}

	// 自定义 Transport：TCP 连 ip，SNI 用 host
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, fmt.Sprintf("%s:%d", ip, port))
			},
			TLSClientConfig: &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: true,
			},
		},
	}

	reqURL := fmt.Sprintf("%s://%s", scheme, host)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	// 模拟浏览器请求头，绕过简单反爬
	req.Header.Set("User-Agent",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36")
	req.Header.Set("Accept",
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	req.Header.Set("Connection", "close")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	conn, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer conn.Body.Close()

	for k, v := range conn.Header {
		headers.WriteString(k)
		headers.WriteString(": ")
		headers.WriteString(strings.Join(v, ";"))
		headers.WriteString("\n")
	}

	//获取cookies,跟上面headers一样拼接成一个字符串
	var cookies strings.Builder

	for _, c := range conn.Cookies() {
		cookies.WriteString(c.Name)
		cookies.WriteString("=")
		cookies.WriteString(c.Value)
		cookies.WriteString("; ")
	}

	var title string
	body, _ := io.ReadAll(io.LimitReader(conn.Body, 1024*1024))
	re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	match := re.FindStringSubmatch(string(body))

	if len(match) > 1 {
		title = match[1]
	}

	httpresult := fingerprint.HTTPResult{
		Title:   title,
		Headers: headers.String(),
		Body:    string(body),
		Cookies: cookies.String(),
	}

	favHashes := fingerprint.GetFavicon(reqURL, string(body))

	fps1 := fingerprint.Matchfinger(httpresult)
	fps2 := fingerprint.MatchFavicon(favHashes)

	allfps := append(fps1, fps2...)

	return &HttpInfo{
		Status:       conn.Status,
		Title:        title,
		Headers:      headers.String(),
		Body:         string(body),
		Server:       conn.Header.Get("Server"),
		Fingerprints: strings.Join(allfps, ","),
	}, nil
}

// Display 将info存在的部分转化为字符串
func (h *HttpInfo) Display() string {
	var parts []string

	if h.Status != "" {
		parts = append(parts, h.Status)
	}

	if h.Server != "" {
		parts = append(parts, "Server: "+h.Server)
	}

	if h.Title != "" {
		parts = append(parts, "Title: "+h.Title)
	}

	if h.Fingerprints != "" {
		parts = append(parts, "FP: "+h.Fingerprints)
	}

	return strings.Join(parts, " | ")
}

func bannerClean(raw string) string {
	var b strings.Builder
	for _, r := range raw {
		if r >= 32 && r < 127 {
			b.WriteRune(r)
		} else if r == '\n' || r == '\r' || r == '\t' {
			b.WriteByte(' ')
		} else {
			b.WriteByte('.')
		}
	}
	return strings.TrimSpace(b.String())
}
