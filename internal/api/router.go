//路由注册,找到对应的接口

package api

import (
	"github.com/gin-gonic/gin"
	"github.com/shen060606/sma11sCan/internal/api/handler"
	"github.com/shen060606/sma11sCan/internal/api/middleware"
)

// r的类型就是gin.Engine，r:=gin.default()
func Setup() *gin.Engine {
	r := gin.New()
	r.Use(middleware.Logger(), middleware.Recovery())
	r.LoadHTMLGlob("static/*")

	//首页
	r.GET("/", func(c *gin.Context) {
		c.HTML(200, "index.html", nil)
	})

	api := r.Group("/api/v1")
	{
		api.POST("/scan", handler.CreateScan)
		api.GET("/scans", handler.QueryPage)
		api.GET("/scans/list", handler.ScanList)

	}

	return r
}
