package model

import (
	"fmt"

	"github.com/skye-z/uac/oauth2"
	oauth2pkg "github.com/skye-z/uac/oauth2/pkg"
)

type TestStorage struct {
	clients   map[string]oauth2pkg.Client
	authorize map[string]*oauth2pkg.Authorize
	access    map[string]*oauth2pkg.Access
	refresh   map[string]string
}

func NewTestStorage() *TestStorage {
	r := &TestStorage{
		clients:   make(map[string]oauth2pkg.Client),
		authorize: make(map[string]*oauth2pkg.Authorize),
		access:    make(map[string]*oauth2pkg.Access),
		refresh:   make(map[string]string),
	}

	r.clients["1234"] = &oauth2pkg.ClientData{
		Id:          "1234",
		Secret:      "aabbccdd",
		RedirectUri: "http://localhost:12600/test",
	}

	return r
}

func (s *TestStorage) Clone() oauth2pkg.Store {
	return s
}

func (s *TestStorage) Close() {
}

func (s *TestStorage) GetName() string {
	return "memory"
}

func (s *TestStorage) GetClient(id string) (oauth2pkg.Client, error) {
	fmt.Printf("GetClient: %s\n", id)
	if c, ok := s.clients[id]; ok {
		return c, nil
	}
	return nil, oauth2.Errors.ImplementNotFound.Throw()
}

func (s *TestStorage) SaveClient(id string, client oauth2pkg.Client) error {
	fmt.Printf("SaveClient: %s\n", id)
	s.clients[id] = client
	return nil
}

func (s *TestStorage) SaveAuthorize(data *oauth2pkg.Authorize) error {
	fmt.Printf("SaveAuthorize: %s\n", data.Code)
	s.authorize[data.Code] = data
	return nil
}

func (s *TestStorage) GetAuthorize(code string) (*oauth2pkg.Authorize, error) {
	fmt.Printf("GetAuthorize: %s\n", code)
	if d, ok := s.authorize[code]; ok {
		return d, nil
	}
	return nil, oauth2.Errors.ImplementNotFound.Throw()
}

func (s *TestStorage) RemoveAuthorize(code string) error {
	fmt.Printf("RemoveAuthorize: %s\n", code)
	delete(s.authorize, code)
	return nil
}

func (s *TestStorage) SaveAccess(data *oauth2pkg.Access) error {
	fmt.Printf("SaveAccess: %s\n", data.AccessToken)
	s.access[data.AccessToken] = data
	if data.RefreshToken != "" {
		s.refresh[data.RefreshToken] = data.AccessToken
	}
	return nil
}

func (s *TestStorage) GetAccess(code string) (*oauth2pkg.Access, error) {
	fmt.Printf("GetAccess: %s\n", code)
	if d, ok := s.access[code]; ok {
		return d, nil
	}
	return nil, oauth2.Errors.ImplementNotFound.Throw()
}

func (s *TestStorage) RemoveAccess(code string) error {
	fmt.Printf("RemoveAccess: %s\n", code)
	delete(s.access, code)
	return nil
}

func (s *TestStorage) GetRefresh(code string) (*oauth2pkg.Access, error) {
	fmt.Printf("GetRefresh: %s\n", code)
	if d, ok := s.refresh[code]; ok {
		return s.GetAccess(d)
	}
	return nil, oauth2.Errors.ImplementNotFound.Throw()
}

func (s *TestStorage) RemoveRefresh(code string) error {
	fmt.Printf("RemoveRefresh: %s\n", code)
	delete(s.refresh, code)
	return nil
}
