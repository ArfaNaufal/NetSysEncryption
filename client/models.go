package main

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

type Message struct {
	Type    string `json:"type"`
	From    string `json:"from"`
	To      string `json:"to"`
	Payload string `json:"payload"`
}
