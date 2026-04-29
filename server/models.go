package main

import (
	"sync"

	"github.com/gorilla/websocket"
)

type Message struct {
	Type    string `json:"type"`
	From    string `json:"from"`
	To      string `json:"to"`
	Payload string `json:"payload"`
}

type RegisterPayload struct {
	Token           string            `json:"token"`
	RegID           uint32            `json:"regId"`
	DeviceID        uint32            `json:"deviceId"`
	SignedPreKeyID  uint32            `json:"signedPreKeyId"`
	SignedPreKeyPub []byte            `json:"signedPreKeyPub"`
	Signature       []byte            `json:"signature"`
	IdentityPub     []byte            `json:"identityPub"`
	PreKeys         map[uint32][]byte `json:"preKeys"`
}

type UserRecord struct {
	Token           string
	RegID           uint32
	DeviceID        uint32
	SignedPreKeyID  uint32
	SignedPreKeyPub []byte
	Signature       []byte
	IdentityPub     []byte
	PreKeys         map[uint32][]byte
}

type ExchangeBundle struct {
	RegID           uint32 `json:"regId"`
	DeviceID        uint32 `json:"deviceId"`
	PreKeyID        uint32 `json:"preKeyId"`
	PreKeyPub       []byte `json:"preKeyPub"`
	SignedPreKeyID  uint32 `json:"signedPreKeyId"`
	SignedPreKeyPub []byte `json:"signedPreKeyPub"`
	Signature       []byte `json:"signature"`
	IdentityPub     []byte `json:"identityPub"`
}

type Client struct {
	Conn *websocket.Conn
	mu   sync.Mutex
}

func (c *Client) WriteJSON(v interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Conn.WriteJSON(v)
}
