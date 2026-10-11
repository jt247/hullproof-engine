package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
)

func main() {
	_ = pgx.Identifier{}
	r := gin.Default()
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
}
