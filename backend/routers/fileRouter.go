package routers

import (
	"project1/controllers"
	"project1/middlewares"

	"github.com/gin-gonic/gin"
)

func RegisterFileRouter(api *gin.RouterGroup, fileController *controllers.FileController) {
	files := api.Group("/files", middlewares.AuthMiddleware())
	files.POST("", fileController.Upload)
	files.GET("", fileController.List)
	files.GET("/:id", fileController.Get)
	files.POST("/:id/decrypt", fileController.Decrypt)
}
