package router

import (
	"github.com/gin-gonic/gin"
	"github.com/sayasurvey/golang/api/controller"
	"github.com/sayasurvey/golang/middleware"
)

func GetRouter() *gin.Engine {
	r := gin.Default()

	r.GET("/", controller.SayHello)
	r.POST("api/login", controller.Login)

	api := r.Group("/api", middleware.JWTAuthMiddleware())
	{
		api.POST("/register", controller.Register)
		api.POST("/logout", controller.Logout)
		api.GET("/users", controller.GetUsers)
	}

	return r
}
