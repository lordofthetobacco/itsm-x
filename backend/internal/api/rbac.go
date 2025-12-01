package api

import (
	"context"
	"net/http"

	"itsm.x/internal/db"

	"github.com/gin-gonic/gin"
)

func HasPermission(ctx context.Context, user *db.User, permissionName string) (bool, error) {
	permissions, err := db.GetUserPermissions(ctx, user.ID)
	if err != nil {
		return false, err
	}

	for _, perm := range permissions {
		if perm == permissionName {
			return true, nil
		}
	}

	return false, nil
}

func RequirePermission(permissionName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, err := GetUserFromContext(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found in context"})
			c.Abort()
			return
		}

		hasPermission, err := db.CheckUserPermission(c.Request.Context(), user.ID, permissionName)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check permission"})
			c.Abort()
			return
		}

		if !hasPermission {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func RequireAnyPermission(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, err := GetUserFromContext(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found in context"})
			c.Abort()
			return
		}

		for _, perm := range permissions {
			hasPermission, err := db.CheckUserPermission(c.Request.Context(), user.ID, perm)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check permission"})
				c.Abort()
				return
			}

			if hasPermission {
				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		c.Abort()
	}
}

func RequireAllPermissions(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, err := GetUserFromContext(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found in context"})
			c.Abort()
			return
		}

		for _, perm := range permissions {
			hasPermission, err := db.CheckUserPermission(c.Request.Context(), user.ID, perm)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check permission"})
				c.Abort()
				return
			}

			if !hasPermission {
				c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}
