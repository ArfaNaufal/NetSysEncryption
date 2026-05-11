package main

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func handleRegister(c echo.Context) error {
	userID := c.Param("id")

	var payload RegisterPayload
	if err := c.Bind(&payload); err != nil {
		return c.String(http.StatusBadRequest, "Invalid JSON payload")
	}

	serverMu.Lock()
	defer serverMu.Unlock()

	if existingUser, exists := userDB[userID]; exists {
		if existingUser.Token != payload.Token {
			return c.String(http.StatusUnauthorized, "Unauthorized")
		}
	}

	userDB[userID] = &UserRecord{
		Token:           payload.Token,
		RegID:           payload.RegID,
		DeviceID:        payload.DeviceID,
		SignedPreKeyID:  payload.SignedPreKeyID,
		SignedPreKeyPub: payload.SignedPreKeyPub,
		Signature:       payload.Signature,
		IdentityPub:     payload.IdentityPub,
		PreKeys:         payload.PreKeys,
	}

	return c.NoContent(http.StatusOK)
}

func handleGetBundle(c echo.Context) error {
	userID := c.Param("id")

	serverMu.Lock()
	defer serverMu.Unlock()

	user, exists := userDB[userID]
	if !exists {
		return c.String(http.StatusNotFound, "User not found")
	}

	var pkID uint32
	var pkPub []byte
	for id, pub := range user.PreKeys {
		pkID = id
		pkPub = pub
		delete(user.PreKeys, id)
		break
	}

	if pkPub == nil {
		return c.String(http.StatusServiceUnavailable, "User exhausted PreKeys")
	}

	bundle := ExchangeBundle{
		RegID:           user.RegID,
		DeviceID:        user.DeviceID,
		PreKeyID:        pkID,
		PreKeyPub:       pkPub,
		SignedPreKeyID:  user.SignedPreKeyID,
		SignedPreKeyPub: user.SignedPreKeyPub,
		Signature:       user.Signature,
		IdentityPub:     user.IdentityPub,
	}

	return c.JSON(http.StatusOK, bundle)
}

func handleWebSocket(c echo.Context) error {
	userID := c.Param("id")
	token := c.QueryParam("token")

	serverMu.RLock()
	user, exists := userDB[userID]
	valid := exists && user.Token == token
	serverMu.RUnlock()

	if !valid {
		return c.String(http.StatusUnauthorized, "Unauthorized WS Access")
	}

	conn, err := upgrader.Upgrade(c.Response().Writer, c.Request(), nil)
	if err != nil {
		return err
	}
	client := &Client{Conn: conn}

	serverMu.Lock()
	clients[userID] = client
	serverMu.Unlock()

	defer func() {
		serverMu.Lock()
		delete(clients, userID)
		delete(userDB, userID)
		serverMu.Unlock()
		client.Conn.Close()
	}()

	for {
		var msg Message
		if err := client.Conn.ReadJSON(&msg); err != nil {
			break
		}

		serverMu.RLock()
		targetClient, isOnline := clients[msg.To]
		serverMu.RUnlock()

		if isOnline {
			targetClient.WriteJSON(msg)
		} else {
			client.WriteJSON(Message{Type: "error", From: "server", To: msg.From, Payload: "User offline!"})
		}
	}

	return nil
}
