package middlewares

import (
	"math"
	"net/http"

	"project1/utils"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		tokenString, err := ctx.Cookie("access_token")
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": "Missing authentication cookie",
			})
			return
		}

		claims, err := utils.ValidateToken(tokenString)

		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": "Invalid or expired token",
			})
			return
		}

		val, exist := claims["userId"]
		userID, ok := val.(float64)
		if !exist || !ok || userID < 0 || userID != math.Trunc(userID) {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthorized: user_id missing",
			})
			return
		}

		ctx.Set("userID", uint(userID))
		ctx.Next()
	}
}
