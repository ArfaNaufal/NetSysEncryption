package main

import (
	"context"
	"fmt"
	"log"

	"go.mau.fi/libsignal/keys/identity"
	"go.mau.fi/libsignal/keys/prekey"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/serialize"
	"go.mau.fi/libsignal/session"
	"go.mau.fi/libsignal/state/record"
	"go.mau.fi/libsignal/util/keyhelper"
	"go.mau.fi/libsignal/util/optional"
)

// ==========================================
// Phase 1: Modern Context-Aware Store
// ==========================================

type InMemoryStore struct {
	localId       uint32
	identityKey   *identity.KeyPair
	preKeys       map[uint32]*record.PreKey
	signedPreKeys map[uint32]*record.SignedPreKey
	sessions      map[string]*record.Session
	identities    map[string]*identity.Key
	serializer    *serialize.Serializer
}

func NewInMemoryStore(id uint32, keyPair *identity.KeyPair, ser *serialize.Serializer) *InMemoryStore {
	return &InMemoryStore{
		localId:       id,
		identityKey:   keyPair,
		preKeys:       make(map[uint32]*record.PreKey),
		signedPreKeys: make(map[uint32]*record.SignedPreKey),
		sessions:      make(map[string]*record.Session),
		identities:    make(map[string]*identity.Key),
		serializer:    ser,
	}
}

// -- IdentityKeyStore --
func (s *InMemoryStore) GetIdentityKeyPair() *identity.KeyPair { return s.identityKey }
func (s *InMemoryStore) GetLocalRegistrationID() uint32        { return s.localId } // Fixed capitalized ID
func (s *InMemoryStore) SaveIdentity(ctx context.Context, address *protocol.SignalAddress, key *identity.Key) error {
	s.identities[address.Name()] = key
	return nil
}
func (s *InMemoryStore) IsTrustedIdentity(ctx context.Context, address *protocol.SignalAddress, key *identity.Key) (bool, error) {
	return true, nil // Trust all keys for the PoC
}
func (s *InMemoryStore) GetIdentity(ctx context.Context, address *protocol.SignalAddress) (*identity.Key, error) {
	return s.identities[address.Name()], nil
}

// -- PreKeyStore --
func (s *InMemoryStore) LoadPreKey(ctx context.Context, id uint32) (*record.PreKey, error) { return s.preKeys[id], nil }
func (s *InMemoryStore) StorePreKey(ctx context.Context, id uint32, key *record.PreKey) error {
	s.preKeys[id] = key
	return nil
}
func (s *InMemoryStore) ContainsPreKey(ctx context.Context, id uint32) (bool, error) {
	_, ok := s.preKeys[id]
	return ok, nil
}
func (s *InMemoryStore) RemovePreKey(ctx context.Context, id uint32) error {
	delete(s.preKeys, id)
	return nil
}

// -- SignedPreKeyStore --
func (s *InMemoryStore) LoadSignedPreKey(ctx context.Context, id uint32) (*record.SignedPreKey, error) {
	return s.signedPreKeys[id], nil
}
func (s *InMemoryStore) LoadSignedPreKeys(ctx context.Context) ([]*record.SignedPreKey, error) {
	var keys []*record.SignedPreKey
	for _, k := range s.signedPreKeys {
		keys = append(keys, k)
	}
	return keys, nil
}
func (s *InMemoryStore) StoreSignedPreKey(ctx context.Context, id uint32, key *record.SignedPreKey) error {
	s.signedPreKeys[id] = key
	return nil
}
func (s *InMemoryStore) ContainsSignedPreKey(ctx context.Context, id uint32) (bool, error) {
	_, ok := s.signedPreKeys[id]
	return ok, nil
}
func (s *InMemoryStore) RemoveSignedPreKey(ctx context.Context, id uint32) error {
	delete(s.signedPreKeys, id)
	return nil
}

// -- SessionStore --
func (s *InMemoryStore) LoadSession(ctx context.Context, address *protocol.SignalAddress) (*record.Session, error) {
	if session, ok := s.sessions[address.Name()]; ok {
		return session, nil
	}
	return record.NewSession(s.serializer.Session, s.serializer.State), nil
}
func (s *InMemoryStore) StoreSession(ctx context.Context, address *protocol.SignalAddress, session *record.Session) error {
	s.sessions[address.Name()] = session
	return nil
}
func (s *InMemoryStore) ContainsSession(ctx context.Context, address *protocol.SignalAddress) (bool, error) {
	_, ok := s.sessions[address.Name()]
	return ok, nil
}
// Fixed: strict error return expected by the modern store interface
func (s *InMemoryStore) DeleteSession(ctx context.Context, address *protocol.SignalAddress) error {
	delete(s.sessions, address.Name())
	return nil 
}
func (s *InMemoryStore) GetSubDeviceSessions(ctx context.Context, name string) ([]uint32, error) {
	return []uint32{}, nil
}
func (s *InMemoryStore) DeleteAllSessions(ctx context.Context) error {
	s.sessions = make(map[string]*record.Session)
	return nil
}

// ==========================================
// Phase 2: Core E2EE Execution
// ==========================================

func main() {
	ctx := context.TODO()
	serializer := serialize.NewJSONSerializer()

	// 1. Initialize Bob (Recipient)
	bobIdentity, _ := keyhelper.GenerateIdentityKeyPair()
	bobStore := NewInMemoryStore(keyhelper.GenerateRegistrationID(), bobIdentity, serializer)
	bobAddress := protocol.NewSignalAddress("bob", 1)

	// Bob generates PreKeys
	bobPreKeys, _ := keyhelper.GeneratePreKeys(0, 1, serializer.PreKeyRecord)
	bobSignedPreKey, _ := keyhelper.GenerateSignedPreKey(bobIdentity, 0, serializer.SignedPreKeyRecord)

	bobStore.StorePreKey(ctx, bobPreKeys[0].ID().Value, bobPreKeys[0])
	bobStore.StoreSignedPreKey(ctx, bobSignedPreKey.ID(), bobSignedPreKey)

	// 2. Initialize Alice (Sender)
	aliceIdentity, _ := keyhelper.GenerateIdentityKeyPair()
	aliceStore := NewInMemoryStore(keyhelper.GenerateRegistrationID(), aliceIdentity, serializer)
	aliceAddress := protocol.NewSignalAddress("alice", 1)

	// 3. X3DH - Alice builds session
	// Fixed: Properly initialized Optional Uint32
	pkID := optional.NewOptionalUint32(bobPreKeys[0].ID().Value)

	// Fixed: Arguments aligned to modern NewBundle signature
	bobPreKeyBundle := prekey.NewBundle(
		bobStore.GetLocalRegistrationID(),
		bobAddress.DeviceID(),
		pkID,
		bobSignedPreKey.ID(),
		bobPreKeys[0].KeyPair().PublicKey(),
		bobSignedPreKey.KeyPair().PublicKey(),
		bobSignedPreKey.Signature(),
		bobIdentity.PublicKey(),
	)

	aliceBuilder := session.NewBuilder(aliceStore, aliceStore, aliceStore, aliceStore, bobAddress, serializer)
	err := aliceBuilder.ProcessBundle(ctx, bobPreKeyBundle)
	if err != nil {
		log.Fatal("Handshake failed:", err)
	}

	// 4. Double Ratchet - Alice encrypts message
	msg := []byte("Hello Bob, the text is securely encrypted!")
	aliceCipher := session.NewCipher(aliceBuilder, bobAddress)

	ciphertext, _ := aliceCipher.Encrypt(ctx, msg)
	fmt.Printf("Alice sent Encrypted Type: %d\n", ciphertext.Type())

	// 5. Bob decrypts message
	bobBuilder := session.NewBuilder(bobStore, bobStore, bobStore, bobStore, aliceAddress, serializer)
	bobCipher := session.NewCipher(bobBuilder, aliceAddress)

	var plaintext []byte
	if ciphertext.Type() == protocol.PREKEY_TYPE {
		plaintext, _ = bobCipher.DecryptMessage(ctx, ciphertext.(*protocol.PreKeySignalMessage))
	} else {
		plaintext, _ = bobCipher.Decrypt(ctx, ciphertext.(*protocol.SignalMessage))
	}

	fmt.Printf("Bob decrypted: %s\n", string(plaintext))
}