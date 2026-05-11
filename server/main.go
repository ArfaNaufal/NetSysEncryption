package main

import (
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// Global state dan konfigurasi
var (
	upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	clients  = make(map[string]*Client)
	userDB   = make(map[string]*UserRecord)
	serverMu sync.RWMutex
)

func main() {
	e := echo.New()

	e.Use(middleware.RequestLogger())
	e.Use(middleware.Recover())

	e.GET("/ws/:id", handleWebSocket)
	e.POST("/register/:id", handleRegister)
	e.GET("/bundle/:id", handleGetBundle)

	e.Logger.Fatal(e.Start(":8080"))
}
