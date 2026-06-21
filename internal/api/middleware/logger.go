// 打印日志加上扫描时间
package middleware

import (
	"log"
	"time"

	"github.com/gin-gonic/gin"
)

func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		c.Next() //执行后面的handler

		latency := time.Since(start)
		status := c.Writer.Status()

		//正常请求用info，错误请求用warn
		if status >= 500 {
			log.Printf("[WARNING] %s %s %d %v", c.Request.Method, path, status, latency)
		} else {
			log.Printf("[INFO] %s %s %d %v", c.Request.Method, path, status, latency)
		}
	}
}
