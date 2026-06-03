package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

func Bannerget(ip string, port int) string {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second) //tcp链接建立成功后，等待信息的超时时间

	if err != nil {
		//fmt.Println(err)
		return ""
	}

	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	buf := make([]byte, 1024)

	n, err := conn.Read(buf) //读取conn的内容并写进buf里面

	if err != nil {
		return ""
	}

	result := strings.TrimSpace(string(buf[:n])) //把切片的有效部分转化成字符串，并且去除空格部分
	return BannerClean(result)

}

type HttpInfo struct {
	Status       string
	Title        string
	Headers      string
	Body         string
	Server       string
	Fingerprints string
}

// 80,443,8080端口http请求
func Httpbannerget(ip string, port int) (*HttpInfo, error) {
	var headers strings.Builder //创建一个可拼接的字符串

	var ipaddr string
	if port == 80 || port == 8080 {
		ipaddr = fmt.Sprintf("http://%s:%d", ip, port)
	} else {
		ipaddr = fmt.Sprintf("https://%s:%d", ip, port)
	}

	//跳过整数验证
	client := &http.Client{ //创建一个结构体,下面都是配置
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	conn, err := client.Get(ipaddr)
	if err != nil {
		return nil, err
	}
	defer conn.Body.Close()

	for k, v := range conn.Header {
		headers.WriteString(k)
		headers.WriteString(": ")
		headers.WriteString(strings.Join(v, ";")) //把一个数组（切片）里的多个值，用指定符号连起来
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
	//title = ""                                           //默认为空
	body, _ := io.ReadAll(io.LimitReader(conn.Body, 1024*1024)) //提取body里面的title
	re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)        //(.*?)是捕获组
	match := re.FindStringSubmatch(string(body))

	if len(match) > 1 {
		title = match[1]
	}

	//body, _ := io.ReadAll(conn.Body)  //返回body太多了，只要状态码和响应头
	//return conn.Status + "| Server:" + conn.Header.Get("Server") + "| Title:" + title

	httpresult1 := HTTPResult{
		Title:   title,
		Headers: headers.String(),
		Body:    string(body),
		Cookies: cookies.String(),
	}

	fps := Matchfinger(httpresult1)
	return &HttpInfo{
		Status:       conn.Status,
		Title:        title,
		Headers:      headers.String(),
		Body:         string(body),
		Server:       conn.Header.Get("Server"),
		Fingerprints: strings.Join(fps, ","),
	}, nil

}

// 将info存在的部分转化为字符串，然后赋值给banner
func (h *HttpInfo) Display() string {
	s := h.Status
	if h.Server != "" {
		s += " | Server: " + h.Server
	}
	if h.Title != "" {
		s += " | Title: " + h.Title
	}
	return s
}

func BannerIdentify(port int, banner string) string {
	// 第一层：Banner 关键词匹配（最准）
	if banner != "" {
		b := strings.ToLower(banner)

		if strings.Contains(b, "ssh-2.0") || strings.Contains(b, "openssh") {
			return "SSH"
		}
		if strings.Contains(b, "220 ") {
			if strings.Contains(b, "esmtp") || strings.Contains(b, "postfix") || strings.Contains(b, "sendmail") {
				return "SMTP"
			}
			if strings.Contains(b, "ftp") || strings.Contains(b, "proftpd") || strings.Contains(b, "vsftpd") {
				return "FTP"
			}
			if strings.Contains(b, "vmware") {
				return "VMware"
			}
			return "SMTP/FTP"
		}
		if strings.Contains(b, "caching_sha2") || strings.Contains(b, "mysql") {
			return "MySQL"
		}
		if strings.Contains(b, "+ok") {
			return "POP3"
		}
		if strings.Contains(b, "* ok") || strings.Contains(b, "imap4") {
			return "IMAP"
		}
		if strings.Contains(b, "redis") || strings.Contains(b, "-err") {
			return "Redis"
		}
		if strings.Contains(b, "mongodb") {
			return "MongoDB"
		}
		if strings.Contains(b, "rdp") || strings.Contains(b, "tpkt") {
			return "RDP"
		}
		if strings.Contains(b, "telnet") {
			return "Telnet"
		}
		if strings.Contains(b, "dovecot") {
			return "Dovecot"
		}
		if strings.Contains(b, "postgresql") || strings.Contains(b, "postgres") {
			return "PostgreSQL"
		}
		if strings.Contains(b, "mssql") || strings.Contains(b, "sql server") {
			return "MSSQL"
		}
		if strings.HasPrefix(b, "http/") || strings.Contains(b, "server:") {
			return "HTTP"
		}
	}

	// 第二层：端口表兜底
	if svc := Top_port()[port]; svc != "" {
		return svc
	}

	// 第三层：未知
	return ""
}

func BannerClean(raw string) string {
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
