package api

import (
	"fmt"
	"net/http"
	"strings"

	"itsm.x/internal/auth"
	"itsm.x/internal/db"

	"github.com/gin-gonic/gin"
)

const UserContextKey = "user"

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization header required"})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
			c.Abort()
			return
		}

		tokenString := parts[1]
		claims, err := auth.ValidateToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			c.Abort()
			return
		}

		user, err := db.GetUserByID(c.Request.Context(), claims.UserID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
			c.Abort()
			return
		}

		c.Set(UserContextKey, user)
		c.Next()
	}
}

func GetUserFromContext(c *gin.Context) (*db.User, error) {
	user, exists := c.Get(UserContextKey)
	if !exists {
		return nil, fmt.Errorf("user not found in context")
	}

	userObj, ok := user.(*db.User)
	if !ok {
		return nil, fmt.Errorf("invalid user type in context")
	}

	return userObj, nil
}

