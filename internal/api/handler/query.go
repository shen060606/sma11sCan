// 历史查询相关接口
package handler

import (
	"github.com/gin-gonic/gin"
	"github.com/shen060606/sma11sCan/global"
	"github.com/shen060606/sma11sCan/internal/api/response"
)

// 历史查询页面
func QueryPage(c *gin.Context) {
	c.HTML(200, "query.html", nil)
}

// 扫描历史列表（按批次分组）
func ScanList(c *gin.Context) {
	tasks, err := global.GetAllTasks()
	if err != nil {
		response.ServerError(c, "查询记录失败")
		return
	}
	response.OK(c, tasks)
}
