package main

import (
	"regexp"
	"strings"
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

// 每个web页面的信息
type HTTPResult struct {
	Title       string
	Headers     string
	Body        string
	Cookies     string
	FaviconHash int32
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
