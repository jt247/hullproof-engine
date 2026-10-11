package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

var db *gorm.DB
var validate = validator.New()

type Note struct {
	ID      uint
	Title   string
	OwnerID uint
}

type NoteInput struct {
	Title string `json:"title" binding:"required,max=200" validate:"required,max=200"`
}

type ProfileInput struct {
	Email string `json:"email" validate:"required,email"`
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
	api := r.Group("/api", AuthRequired())
	api.POST("/notes", func(c *gin.Context) {
		var in NoteInput
		if err := c.ShouldBindJSON(&in); err != nil || validate.Struct(&in) != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		n := Note{Title: in.Title, OwnerID: c.MustGet("user").(uint)}
		db.Create(&n)
		c.JSON(http.StatusCreated, n)
	})
	api.DELETE("/notes/:id", func(c *gin.Context) {
		db.Where("id = ? AND owner_id = ?", c.Param("id"), c.MustGet("user")).Delete(&Note{})
		c.Status(http.StatusNoContent)
	})
	api.PUT("/profile", func(c *gin.Context) {
		var in ProfileInput
		if err := c.ShouldBindJSON(&in); err != nil || validate.Struct(&in) != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		db.Model(&Note{}).Where("owner_id = ?", c.MustGet("user")).Updates(&in)
		c.Status(http.StatusNoContent)
	})
	r.Run(":3000")
}
