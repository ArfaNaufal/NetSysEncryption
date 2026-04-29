package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/websocket"
	"go.mau.fi/libsignal/ecc"
	"go.mau.fi/libsignal/keys/identity"
	"go.mau.fi/libsignal/keys/prekey"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/serialize"
	"go.mau.fi/libsignal/session"
	"go.mau.fi/libsignal/util/keyhelper"
	"go.mau.fi/libsignal/util/optional"
)

var (
	myName     string
	myToken    string
	store      *InMemoryStore
	wsConn     *websocket.Conn
	serializer *serialize.Serializer
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Print("Username : ")
	scanner.Scan()
	myName = strings.TrimSpace(scanner.Text())

	fmt.Print("Token    : ")
	scanner.Scan()
	myToken = strings.TrimSpace(scanner.Text())

	serializer = serialize.NewJSONSerializer()
	identityKeyPair, _ := keyhelper.GenerateIdentityKeyPair()
	store = NewInMemoryStore(keyhelper.GenerateRegistrationID(), identityKeyPair, serializer)

	generateAndRegisterKeys()

	serverURL := fmt.Sprintf("ws://localhost:8080/ws/%s?token=%s", myName, myToken)
	conn, _, err := websocket.DefaultDialer.Dial(serverURL, nil)
	if err != nil {
		fmt.Println("[Error] Gagal terhubung ke WebSocket server.")
		os.Exit(1)
	}
	wsConn = conn
	defer wsConn.Close()

	go receiveMessages()

	for {
		fmt.Printf("\n-- Menu [%s] --\n1. Chat\n2. Keluar\nPilih > ", myName)
		scanner.Scan()
		choice := scanner.Text()

		switch choice {
		case "1":
			fmt.Print("Nama Target: ")
			scanner.Scan()
			target := strings.TrimSpace(scanner.Text())
			if target != "" {
				chatLoop(target, scanner)
			}
		case "2":
			fmt.Println("Program dihentikan.")
			return
		default:
			fmt.Println("Pilihan tidak valid.")
		}
	}
}

func generateAndRegisterKeys() {
	fmt.Println("[System] Membuat kunci kriptografi...")
	preKeys, _ := keyhelper.GeneratePreKeys(0, 10, serializer.PreKeyRecord)
	signedPreKey, _ := keyhelper.GenerateSignedPreKey(store.GetIdentityKeyPair(), 0, serializer.SignedPreKeyRecord)

	store.StoreSignedPreKey(context.TODO(), signedPreKey.ID(), signedPreKey)

	preKeyMap := make(map[uint32][]byte)
	for _, pk := range preKeys {
		store.StorePreKey(context.TODO(), pk.ID().Value, pk)
		preKeyMap[pk.ID().Value] = pk.KeyPair().PublicKey().Serialize()
	}

	sig := signedPreKey.Signature()
	payload := RegisterPayload{
		Token:           myToken,
		RegID:           store.GetLocalRegistrationID(),
		DeviceID:        1,
		SignedPreKeyID:  signedPreKey.ID(),
		SignedPreKeyPub: signedPreKey.KeyPair().PublicKey().Serialize(),
		Signature:       sig[:],
		IdentityPub:     store.GetIdentityKeyPair().PublicKey().Serialize(),
		PreKeys:         preKeyMap,
	}

	body, _ := json.Marshal(payload)
	resp, err := http.Post(fmt.Sprintf("http://localhost:8080/register/%s", myName), "application/json", bytes.NewBuffer(body))
	if err != nil || resp.StatusCode != http.StatusOK {
		fmt.Println("[Error] Gagal mendaftar. Nama sudah terpakai atau token salah.")
		os.Exit(1)
	}
	fmt.Println("[System] Berhasil login ke jaringan.")
}

func chatLoop(target string, scanner *bufio.Scanner) {
	targetAddr := protocol.NewSignalAddress(target, 1)

	hasSession, _ := store.ContainsSession(context.TODO(), targetAddr)
	if !hasSession {
		fmt.Printf("[System] Meminta kunci publik %s...\n", target)
		resp, err := http.Get(fmt.Sprintf("http://localhost:8080/bundle/%s", target))
		if err != nil || resp.StatusCode != http.StatusOK {
			fmt.Println("[Error] Target tidak ditemukan atau sedang offline.")
			return
		}

		var b ExchangeBundle
		json.NewDecoder(resp.Body).Decode(&b)

		pkPub, _ := ecc.DecodePoint(b.PreKeyPub, 0)
		spkPub, _ := ecc.DecodePoint(b.SignedPreKeyPub, 0)
		idPubEC, _ := ecc.DecodePoint(b.IdentityPub, 0)
		idPub := identity.NewKey(idPubEC)

		var sig [64]byte
		copy(sig[:], b.Signature)

		targetBundle := prekey.NewBundle(
			b.RegID, b.DeviceID, optional.NewOptionalUint32(b.PreKeyID),
			b.SignedPreKeyID, pkPub, spkPub, sig, idPub,
		)

		builder := session.NewBuilder(store, store, store, store, targetAddr, serializer)
		if err := builder.ProcessBundle(context.TODO(), targetBundle); err != nil {
			fmt.Println("[Error] Handshake E2EE gagal.")
			return
		}

		hash := sha256.Sum256(b.IdentityPub)
		fingerprint := hex.EncodeToString(hash[:])
		fmt.Printf("[System] Kanal aman E2EE terbentuk. Fingerprint: %s...\n", fingerprint[:16])
	}

	builder := session.NewBuilder(store, store, store, store, targetAddr, serializer)
	cipher := session.NewCipher(builder, targetAddr)

	fmt.Println("--- Ketik pesan (/exit untuk kembali) ---")
	for {
		fmt.Print("You > ")
		scanner.Scan()
		text := scanner.Text()

		if text == "/exit" {
			break
		}
		if text == "" {
			continue
		}

		ciphertext, err := cipher.Encrypt(context.TODO(), []byte(text))
		if err != nil {
			fmt.Println("[Error] Gagal mengenkripsi pesan.")
			continue
		}

		msg := Message{
			Type:    fmt.Sprintf("%d", ciphertext.Type()),
			From:    myName,
			To:      target,
			Payload: base64.StdEncoding.EncodeToString(ciphertext.Serialize()),
		}
		wsConn.WriteJSON(msg)
	}
}

func receiveMessages() {
	for {
		var msg Message
		if err := wsConn.ReadJSON(&msg); err != nil {
			fmt.Println("\n[System] Koneksi terputus dari server.")
			os.Exit(0)
		}

		if msg.Type == "error" {
			fmt.Printf("\n[Server]: %s\nYou > ", msg.Payload)
			continue
		}

		cipherBytes, err := base64.StdEncoding.DecodeString(msg.Payload)
		if err != nil {
			continue
		}

		targetAddr := protocol.NewSignalAddress(msg.From, 1)
		builder := session.NewBuilder(store, store, store, store, targetAddr, serializer)
		cipher := session.NewCipher(builder, targetAddr)

		var plaintext []byte
		var decryptErr error

		if msg.Type == fmt.Sprintf("%d", protocol.PREKEY_TYPE) {
			prekeyMsg, errParse := protocol.NewPreKeySignalMessageFromBytes(
				cipherBytes,
				serializer.PreKeySignalMessage,
				serializer.SignalMessage,
			)
			if errParse == nil {
				plaintext, decryptErr = cipher.DecryptMessage(context.TODO(), prekeyMsg)
			} else {
				decryptErr = errParse
			}
		} else {
			signalMsg, errParse := protocol.NewSignalMessageFromBytes(
				cipherBytes,
				serializer.SignalMessage,
			)
			if errParse == nil {
				plaintext, decryptErr = cipher.Decrypt(context.TODO(), signalMsg)
			} else {
				decryptErr = errParse
			}
		}

		if decryptErr != nil {
			fmt.Printf("\n[Error Dekripsi dari %s]: %v\nYou > ", msg.From, decryptErr)
		} else {
			fmt.Printf("\n[%s]: %s\nYou > ", msg.From, string(plaintext))
		}
	}
}
