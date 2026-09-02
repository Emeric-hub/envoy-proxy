// Package acme wraps the lego ACME client: account key management, and a
// TokenStore that doubles as lego's challenge.Provider (Present/CleanUp)
// and the data source for challenge/server.go's tiny HTTP responder.
package acme

import "sync"

// TokenStore is deliberately just an in-memory map — HTTP-01 challenges
// are short-lived (created and consumed within one issuance attempt), no
// need to persist them across restarts.
type TokenStore struct {
	mu     sync.RWMutex
	tokens map[string]string // token -> keyAuth
}

func NewTokenStore() *TokenStore {
	return &TokenStore{tokens: make(map[string]string)}
}

// Present and CleanUp implement lego's challenge.Provider interface.
func (s *TokenStore) Present(domain, token, keyAuth string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = keyAuth
	return nil
}

func (s *TokenStore) CleanUp(domain, token, keyAuth string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
	return nil
}

// Get is read by challenge/server.go when answering a validation request.
func (s *TokenStore) Get(token string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.tokens[token]
	return v, ok
}
