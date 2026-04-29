package main

import (
	"context"

	"go.mau.fi/libsignal/keys/identity"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/serialize"
	"go.mau.fi/libsignal/state/record"
)

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

func (s *InMemoryStore) GetIdentityKeyPair() *identity.KeyPair { return s.identityKey }
func (s *InMemoryStore) GetLocalRegistrationID() uint32        { return s.localId }
func (s *InMemoryStore) SaveIdentity(_ context.Context, addr *protocol.SignalAddress, key *identity.Key) error {
	s.identities[addr.Name()] = key
	return nil
}
func (s *InMemoryStore) IsTrustedIdentity(_ context.Context, _ *protocol.SignalAddress, _ *identity.Key) (bool, error) {
	return true, nil
}
func (s *InMemoryStore) GetIdentity(_ context.Context, addr *protocol.SignalAddress) (*identity.Key, error) {
	return s.identities[addr.Name()], nil
}
func (s *InMemoryStore) LoadPreKey(_ context.Context, id uint32) (*record.PreKey, error) {
	return s.preKeys[id], nil
}
func (s *InMemoryStore) StorePreKey(_ context.Context, id uint32, key *record.PreKey) error {
	s.preKeys[id] = key
	return nil
}
func (s *InMemoryStore) ContainsPreKey(_ context.Context, id uint32) (bool, error) {
	_, ok := s.preKeys[id]
	return ok, nil
}
func (s *InMemoryStore) RemovePreKey(_ context.Context, id uint32) error {
	delete(s.preKeys, id)
	return nil
}
func (s *InMemoryStore) LoadSignedPreKey(_ context.Context, id uint32) (*record.SignedPreKey, error) {
	return s.signedPreKeys[id], nil
}
func (s *InMemoryStore) LoadSignedPreKeys(_ context.Context) ([]*record.SignedPreKey, error) {
	return nil, nil
}
func (s *InMemoryStore) StoreSignedPreKey(_ context.Context, id uint32, key *record.SignedPreKey) error {
	s.signedPreKeys[id] = key
	return nil
}
func (s *InMemoryStore) ContainsSignedPreKey(_ context.Context, id uint32) (bool, error) {
	_, ok := s.signedPreKeys[id]
	return ok, nil
}
func (s *InMemoryStore) RemoveSignedPreKey(_ context.Context, id uint32) error {
	delete(s.signedPreKeys, id)
	return nil
}
func (s *InMemoryStore) LoadSession(_ context.Context, addr *protocol.SignalAddress) (*record.Session, error) {
	if sess, ok := s.sessions[addr.Name()]; ok {
		return sess, nil
	}
	return record.NewSession(s.serializer.Session, s.serializer.State), nil
}
func (s *InMemoryStore) StoreSession(_ context.Context, addr *protocol.SignalAddress, sess *record.Session) error {
	s.sessions[addr.Name()] = sess
	return nil
}
func (s *InMemoryStore) ContainsSession(_ context.Context, addr *protocol.SignalAddress) (bool, error) {
	_, ok := s.sessions[addr.Name()]
	return ok, nil
}
func (s *InMemoryStore) DeleteSession(_ context.Context, addr *protocol.SignalAddress) error {
	delete(s.sessions, addr.Name())
	return nil
}
func (s *InMemoryStore) GetSubDeviceSessions(_ context.Context, _ string) ([]uint32, error) {
	return []uint32{}, nil
}
func (s *InMemoryStore) DeleteAllSessions(_ context.Context) error {
	s.sessions = make(map[string]*record.Session)
	return nil
}
