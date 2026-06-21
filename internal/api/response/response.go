// 错误处理，统一响应格式
package response

import "github.com/gin-gonic/gin"

type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"` //如果 Data 赋值为：空，序列化 JSON 时自动忽略这个字段，不输出 data
}

func OK(c *gin.Context, data interface{}) {
	c.JSON(200, Response{Code: 0, Message: "success", Data: data})
}

func Fail(c *gin.Context, httpStatus int, msg string) {
	c.JSON(httpStatus, Response{Code: httpStatus, Message: msg})
}

func BadRequest(c *gin.Context, msg string) {
	Fail(c, 400, msg)
}

func ServerError(c *gin.Context, msg string) {
	Fail(c, 500, msg)
}
