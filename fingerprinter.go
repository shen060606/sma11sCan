package main

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type FingerRule struct {
	Product  string
	Location string
	Keyword  string
	Regex    bool
	Weight   int
}

var FingerDB = []FingerRule{

	// =========================
	// Web Server  (铁证级，一条命中就过)
	// =========================

	{Product: "Nginx", Location: "header", Keyword: "server: nginx", Regex: false, Weight: 95},
	{Product: "Apache", Location: "header", Keyword: "server: apache", Regex: false, Weight: 95},
	{Product: "Apache", Location: "header", Keyword: "server: apache/2", Regex: false, Weight: 95},
	{Product: "IIS", Location: "header", Keyword: "microsoft-iis", Regex: false, Weight: 95},
	{Product: "IIS", Location: "title", Keyword: "IIS Windows", Regex: false, Weight: 40},
	{Product: "Tomcat", Location: "header", Keyword: "apache-coyote", Regex: false, Weight: 90},
	{Product: "Tomcat", Location: "title", Keyword: "Apache Tomcat", Regex: false, Weight: 60},
	{Product: "OpenResty", Location: "header", Keyword: "openresty", Regex: false, Weight: 90},
	{Product: "Tengine", Location: "header", Keyword: "tengine", Regex: false, Weight: 90},
	{Product: "WebLogic", Location: "header", Keyword: "weblogic", Regex: false, Weight: 90},
	{Product: "WebSphere", Location: "header", Keyword: "websphere", Regex: false, Weight: 90},
	{Product: "Caddy", Location: "header", Keyword: "server: caddy", Regex: false, Weight: 75},
	{Product: "Lighttpd", Location: "header", Keyword: "server: lighttpd", Regex: false, Weight: 75},
	{Product: "Jetty", Location: "header", Keyword: "server: jetty", Regex: false, Weight: 75},
	{Product: "JBoss", Location: "header", Keyword: "jboss", Regex: false, Weight: 75},
	{Product: "Gunicorn", Location: "header", Keyword: "gunicorn", Regex: false, Weight: 75},

	// =========================
	// CMS  (正文级+辅助级搭配)
	// =========================

	{Product: "WordPress", Location: "meta", Keyword: `name="generator" content="WordPress`, Regex: false, Weight: 95},
	{Product: "WordPress", Location: "body", Keyword: "wp-content", Regex: false, Weight: 55},
	{Product: "WordPress", Location: "body", Keyword: "wp-includes", Regex: false, Weight: 45},
	{Product: "Drupal", Location: "meta", Keyword: `content="Drupal`, Regex: false, Weight: 70},
	{Product: "Drupal", Location: "body", Keyword: "drupal", Regex: false, Weight: 50},
	{Product: "Joomla", Location: "body", Keyword: "joomla", Regex: false, Weight: 55},
	{Product: "Discuz", Location: "meta", Keyword: `content="Discuz`, Regex: false, Weight: 70},
	{Product: "Discuz", Location: "body", Keyword: "discuz", Regex: false, Weight: 55},
	{Product: "DedeCMS", Location: "body", Keyword: "dedecms", Regex: false, Weight: 55},
	{Product: "PHPCMS", Location: "body", Keyword: "phpcms", Regex: false, Weight: 55},
	{Product: "EmpireCMS", Location: "body", Keyword: "empirecms", Regex: false, Weight: 55},
	{Product: "Ecshop", Location: "body", Keyword: "ecshop", Regex: false, Weight: 55},
	{Product: "Typecho", Location: "body", Keyword: "typecho", Regex: false, Weight: 55},
	{Product: "Z-Blog", Location: "body", Keyword: "zb_system", Regex: false, Weight: 70},
	{Product: "MetInfo", Location: "body", Keyword: "metinfo", Regex: false, Weight: 55},

	// =========================
	// Framework  (Body 关键词多为弱信号，header/cookie 强)
	// =========================

	{Product: "PHP", Location: "header", Keyword: "x-powered-by: php", Regex: false, Weight: 90},
	{Product: "PHP", Location: "header", Keyword: "php/", Regex: false, Weight: 50},
	{Product: "ASP.NET", Location: "header", Keyword: "x-aspnet-version", Regex: false, Weight: 95},
	{Product: "Django", Location: "cookie", Keyword: "csrftoken", Regex: false, Weight: 70},
	{Product: "Django", Location: "body", Keyword: "admin/css/base.css", Regex: false, Weight: 35},
	{Product: "Flask", Location: "cookie", Keyword: "session=", Regex: false, Weight: 25},
	{Product: "Express", Location: "header", Keyword: "x-powered-by: express", Regex: false, Weight: 95},
	{Product: "Laravel", Location: "header", Keyword: "laravel_session", Regex: false, Weight: 90},
	{Product: "Laravel", Location: "header", Keyword: "xsrf-token", Regex: false, Weight: 55},
	{Product: "ThinkPHP", Location: "body", Keyword: "thinkphp", Regex: false, Weight: 60},
	{Product: "ThinkPHP", Location: "body", Keyword: "think_template", Regex: false, Weight: 40},
	{Product: "SpringBoot", Location: "body", Keyword: "whitelabel error page", Regex: false, Weight: 90},
	{Product: "SpringBoot", Location: "body", Keyword: "spring boot", Regex: false, Weight: 50},
	{Product: "Spring", Location: "cookie", Keyword: "jsessionid", Regex: false, Weight: 30},
	{Product: "Struts2", Location: "body", Keyword: "struts", Regex: false, Weight: 55},
	{Product: "Ruby on Rails", Location: "cookie", Keyword: "_session_id", Regex: false, Weight: 55},
	{Product: "Shiro", Location: "header", Keyword: "set-cookie: rememberme=deleteme", Regex: false, Weight: 90},
	{Product: "Shiro", Location: "cookie", Keyword: "rememberme", Regex: false, Weight: 55},

	// =========================
	// DevOps / Middleware  (铁证级标题)
	// =========================

	{Product: "Jenkins", Location: "title", Keyword: "jenkins", Regex: false, Weight: 95},
	{Product: "Jenkins", Location: "header", Keyword: "x-jenkins", Regex: false, Weight: 95},
	{Product: "GitLab", Location: "title", Keyword: "gitlab", Regex: false, Weight: 95},
	{Product: "GitLab", Location: "body", Keyword: "gitlab", Regex: false, Weight: 55},
	{Product: "Grafana", Location: "title", Keyword: "grafana", Regex: false, Weight: 95},
	{Product: "Grafana", Location: "body", Keyword: "grafana-app", Regex: false, Weight: 55},
	{Product: "Kibana", Location: "title", Keyword: "kibana", Regex: false, Weight: 95},
	{Product: "Prometheus", Location: "title", Keyword: "prometheus", Regex: false, Weight: 90},
	{Product: "Nacos", Location: "title", Keyword: "nacos", Regex: false, Weight: 95},
	{Product: "RabbitMQ", Location: "title", Keyword: "rabbitmq management", Regex: false, Weight: 95},
	{Product: "Zabbix", Location: "title", Keyword: "zabbix", Regex: false, Weight: 95},
	{Product: "Elasticsearch", Location: "header", Keyword: "elasticsearch", Regex: false, Weight: 90},
	{Product: "ActiveMQ", Location: "title", Keyword: "activemq admin", Regex: false, Weight: 95},
	{Product: "Swagger", Location: "body", Keyword: "swagger-ui", Regex: false, Weight: 85},
	{Product: "Swagger", Location: "title", Keyword: "swagger", Regex: false, Weight: 55},
	{Product: "Kubernetes", Location: "body", Keyword: "kubernetes", Regex: false, Weight: 50},
	{Product: "phpMyAdmin", Location: "title", Keyword: "phpmyadmin", Regex: false, Weight: 95},
	{Product: "phpMyAdmin", Location: "body", Keyword: "phpmyadmin", Regex: false, Weight: 55},

	// =========================
	// OA / 企业应用
	// =========================

	{Product: "泛微OA", Location: "body", Keyword: "/js/wego/", Regex: false, Weight: 75},
	{Product: "泛微OA", Location: "title", Keyword: "泛微", Regex: false, Weight: 55},
	{Product: "致远OA", Location: "title", Keyword: "致远协同", Regex: false, Weight: 90},
	{Product: "致远OA", Location: "body", Keyword: "/seeyon/", Regex: false, Weight: 65},
	{Product: "蓝凌OA", Location: "body", Keyword: "landray", Regex: false, Weight: 75},
	{Product: "用友NC", Location: "body", Keyword: "yyoa", Regex: false, Weight: 70},
	{Product: "用友NC", Location: "title", Keyword: "用友", Regex: false, Weight: 50},
	{Product: "金蝶EAS", Location: "body", Keyword: "kingdee", Regex: false, Weight: 75},
	{Product: "通达OA", Location: "body", Keyword: "td_oa", Regex: false, Weight: 70},
	{Product: "通达OA", Location: "title", Keyword: "通达", Regex: false, Weight: 50},

	// =========================
	// CDN / WAF  (铁证级)
	// =========================

	{Product: "Cloudflare", Location: "header", Keyword: "cf-ray", Regex: false, Weight: 100},
	{Product: "Cloudflare", Location: "header", Keyword: "server: cloudflare", Regex: false, Weight: 100},
	{Product: "阿里云WAF", Location: "header", Keyword: "aliwaf", Regex: false, Weight: 100},
	{Product: "阿里云CDN", Location: "header", Keyword: "ali-cdn", Regex: false, Weight: 95},
	{Product: "360CDN", Location: "header", Keyword: "360wzws", Regex: false, Weight: 100},
	{Product: "百度云加速", Location: "header", Keyword: "yunjiasu", Regex: false, Weight: 95},
	{Product: "腾讯云CDN", Location: "header", Keyword: "tencent-cdn", Regex: false, Weight: 95},

	// =========================
	// 其他常见系统
	// =========================

	{Product: "Harbor", Location: "title", Keyword: "harbor", Regex: false, Weight: 95},
	{Product: "Confluence", Location: "body", Keyword: "confluence", Regex: false, Weight: 80},
	{Product: "Jira", Location: "title", Keyword: "jira", Regex: false, Weight: 90},
	{Product: "SonarQube", Location: "title", Keyword: "sonarqube", Regex: false, Weight: 95},
	{Product: "Nexus", Location: "title", Keyword: "nexus repository", Regex: false, Weight: 95},
	{Product: "Rundeck", Location: "title", Keyword: "rundeck", Regex: false, Weight: 85},
	{Product: "Docker Registry", Location: "header", Keyword: "docker-distribution", Regex: false, Weight: 85},
	{Product: "MinIO", Location: "title", Keyword: "minio console", Regex: false, Weight: 95},
	{Product: "Webmin", Location: "title", Keyword: "webmin", Regex: false, Weight: 85},
	{Product: "Cacti", Location: "title", Keyword: "cacti", Regex: false, Weight: 85},
}

var FaviconDB = map[string][]string{

	// =========================
	// DevOps / 运维平台
	// =========================

	"23e8c7bd78e8cd826c5a6073b15068b1": {"Jenkins"},
	"1c4201c7da53d6c7e48251d3a9680449": {"Nagios"},
	"e298e00b2ff6340343ddf2fc6212010b": {"Nessus"},
	"d80e364c0d3138c7ecd75bf9896f2cad": {"Tomcat"},
	"799f70b71314a7508326d1d2f68f7519": {"JBoss"},
	"04d89d5b7a290334f5ce37c7e8b6a349": {"Jira"},
	"12888a39a499eb041ca42bf456aca285": {"Confluence"},
	"c9339a2ecde0980f40ba22c2d237b94b": {"GLPI"},
	"dcea02a5797ce9e36f19b7590752563e": {"Plesk"},
	"64ca706a50715e421b6c2fa0b32ed7ec": {"Plesk Panel"},

	// =========================
	// OA / 企业系统
	// =========================

	"7dbe9acc2ab6e64d59fa67637b1239df": {"Lotus Domino"},
	"639b61409215d770a99667b446c80ea1": {"Lotus-Domino"},
	"49bf194d1eccb1e5110957d14559d33d": {"OTRS"},
	"f567fd4927f9693a7a2d6cacf21b51b6": {"Horde WebMail"},
	"919e132a62ea07fce13881470ba70293": {"Horde Groupware"},
	"d90cc1762bf724db71d6df86effab63c": {"Vtiger CRM"},
	"b14353fafda7c90fb1a2a214c195de50": {"webERP"},
	"f097f0adf2b9e95a972d21e5e5ab746d": {"Citrix Access"},

	// =========================
	// CMS / 建站系统
	// =========================

	"fa54dbf2f61bd2e0188e47f5f578f736": {"WordPress"},
	"b231ad66a2a9b0eb06f72c4c88973039": {"WordPress"},
	"e44d22b74f7ee4435e22062d5adf4a6a": {"WordPress 2.x"},
	"e6a9dc66179d8c9f34288b16a02f987e": {"Drupal"},
	"b6341dfc213100c61db4fb8775878cec": {"Drupal 7"},
	"c1201c47c81081c7f0930503cae7f71a": {"vBulletin"},
	"8757fcbdbd83b0808955f6735078a287": {"Discuz"},
	"9fac8b45400f794e0799d0d5458c092b": {"Discuz!"},
	"63b982eddd64d44233baa25066db6bc1": {"Joomla"},
	"428b23df874b41d904bbae29057bdba5": {"ECShop"},
	"4cfbb29d0d83685ba99323bc0d4d3513": {"PHPWind"},
	"4eb846f1286ab4e7a399c851d7d84cca": {"Plone CMS"},
	"de68f0ad7b37001b8241bce3887593c7": {"b2evolution"},
	"5b0e3b33aa166c88cee57f83de1d4e55": {"DotNetNuke"},
	"933a83c6e9e47bd1e38424f3789d121d": {"Moodle"},

	// =========================
	// Middleware / 中间件 / 数据库
	// =========================

	"d037ef2f629a22ddadcf438e6be7a325": {"phpMyAdmin"},
	"531b63a51234bb06c9d77f219eb25553": {"phpMyAdmin 4.6+"},
	"a967c8bfde9ea0869637294b679b7251": {"Squid Proxy"},
	"4644f2d45601037b8423d45e13194c93": {"Apache Tomcat"},
	"71e30c507ca3fa005e2d1322a5aa8fb2": {"Apache on Redhat"},
	"eb6d4ce00ec36af7d439ebd4e5a395d7": {"Mailman"},
	"e9469705a8ac323e403d74c11425a62b": {"RoundCube"},
	"ef9c0362bf20a086bb7c2e8ea346b9f0": {"RoundCube 1.0+"},
	"f1ac749564d5ba793550ec6bdc472e7c": {"RoundCube Elastic"},
	"ebe293e1746858d2548bca99c43e4969": {"MantisBT"},
	"701bb703b31f99da18251ca2e557edf0": {"MantisBT 1.2.x"},
	"c126f7e761813946fea2e90ff7ddb838": {"Zenoss"},
	"a4eb4e0aa80740db8d7d951b6d63b2a2": {"ownCloud"},

	// =========================
	// 硬件 / 路由 / NAS / 防火墙
	// =========================

	"531e652a15bc0ad59b6af05019b1834a": {"Synology DSM"},
	"7ff45523a7ee9686d3d391a0a27a0b4f": {"QNAP TurboNAS"},
	"9c003f40e63df95a2b844c6b61448310": {"DD-WRT"},
	"6dcab71e60f0242907940f0fcda69ea5": {"Ubiquiti AirOS"},
	"befcded36aec1e59ea624582fcb3225c": {"SpeedTouch Router"},
	"a8fe5b8ae2c445a33ac41b33ccc9a120": {"Arris Router"},
	"dc0816f371699823e1e03e0078622d75": {"Aruba Network"},
	"f1876a80546b3986dbb79bad727b0374": {"NetScreen Firewall"},
	"240c36cd118aa1ff59986066f21015d4": {"LANCOM Router"},
	"7b0d4bc0ca1659d54469e5013a08d240": {"Netgear ReadyNAS"},
	"d16a0da12074dae41980a6918d33f031": {"ST 605 Router"},
	"ee4a637a1257b2430649d6750cda6eba": {"Trimble Device"},
	"de2b6edbf7930f5dd0ffe0528b2bbcf4": {"Barracuda Firewall"},
}

// 每个web页面的信息
type HTTPResult struct {
	Title       string
	Headers     string
	Body        string
	Cookies     string
	FaviconHash string
}

func Matchfinger(res HTTPResult) []string {

	result := make(map[string]int)

	for _, rule := range FingerDB {
		var target string

		switch rule.Location {

		case "header":
			target = res.Headers
		case "body":
			target = res.Body
		case "cookie":
			target = res.Cookies
		case "title":
			target = res.Title
			// case "favicon":
			// 	target = res.FaviconHash
		}

		target = strings.ToLower(target)
		keyword := strings.ToLower(rule.Keyword)

		if rule.Regex {
			match, _ := regexp.MatchString(keyword, target)
			if match {
				result[rule.Product] += rule.Weight
			}
		} else {
			if strings.Contains(target, keyword) {
				result[rule.Product] += rule.Weight
			}
		}
	}

	var lastresult []string
	for product, value := range result {
		if value >= 80 {
			lastresult = append(lastresult, product)
		}
	}
	return lastresult
}

// 获取favicon，然后返回md5哈希值
func GetFavicon(ip string, body string) []string {
	Client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	base, _ := url.Parse(ip)
	var finalurl []string
	//创建正则对象
	re := regexp.MustCompile(`(?i)<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]+href=["']([^"']+)["']`)
	match := re.FindAllStringSubmatch(body, -1)

	for _, v := range match {
		if len(v) > 1 {

			icon, _ := url.Parse(v[1])
			fullurl := base.ResolveReference(icon).String()
			finalurl = append(finalurl, fullurl)
		}
	}

	// 兜底：如果没找到 icon，默认访问 /favicon.ico（浏览器行为）
	if len(finalurl) == 0 {

		defURL := base.ResolveReference(&url.URL{Path: "/favicon.ico"}).String()
		finalurl = append(finalurl, defURL)
	}

	var hashes []string
	for _, url := range finalurl {
		//获取favicon的hash值

		resp, err := Client.Get(url)
		if err != nil {
			continue
		}

		data, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		hash := md5.Sum(data)
		md5str := fmt.Sprintf("%x", hash)
		hashes = append(hashes, md5str)

		resp.Body.Close()
	}

	return hashes
}

func MatchFavicon(hashes []string) []string {

	result := make(map[string]struct{})

	for _, h := range hashes {

		if products, ok := FaviconDB[h]; ok {

			for _, product := range products {

				result[product] = struct{}{}
			}
		}
	}

	var fps []string

	for k := range result {

		fps = append(fps, k)
	}

	return fps

}
