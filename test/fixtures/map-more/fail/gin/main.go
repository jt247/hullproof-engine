package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

var db *gorm.DB

type Note struct {
	ID      uint
	Title   string
	OwnerID uint
}

type Profile struct {
	ID    uint
	Email string
	Plan  string
}

func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		tok, err := jwt.Parse(c.GetHeader("Authorization"), nil)
		if err != nil || !tok.Valid {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Set("user", tok.Claims)
		c.Next()
	}
}

func main() {
	r := gin.Default()
	r.POST("/api/notes", func(c *gin.Context) {
		var n Note
		c.ShouldBindJSON(&n)
		db.Create(&n)
		c.JSON(http.StatusCreated, n)
	})

	api := r.Group("/api", AuthRequired())
	api.DELETE("/notes/:id", func(c *gin.Context) {
		db.Delete(&Note{}, c.Param("id"))
		c.Status(http.StatusNoContent)
	})
	api.PUT("/profile/:id", func(c *gin.Context) {
		var p Profile
		c.ShouldBindJSON(&p)
		db.Model(&Profile{}).Where("id = ?", c.Param("id")).Updates(&p)
		c.Status(http.StatusNoContent)
	})
	r.Run(":3000")
}
