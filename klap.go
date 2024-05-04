package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"slices"
)

func getNonce() []byte {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		log.Fatalln(err)
	}
	return nonce
}

func hashAuth(user, pass string) [32]byte {
	u := sha1.Sum([]byte(user))
	p := sha1.Sum([]byte(pass))
	a := append(u[:], p[:]...)
	rv := sha256.Sum256(a)
	return rv
}

func hashHandshake1(local_seed, remote_seed, auth_hash []byte) [32]byte {
	return sha256.Sum256(append(append(local_seed, remote_seed...), auth_hash...))
}

func hashHandshake2(local_seed, remote_seed, auth_hash []byte) [32]byte {
	return sha256.Sum256(append(append(remote_seed, local_seed...), auth_hash...))
}

type Klap struct {
	Host     string
	Port     string
	client   http.Client
	authHash []byte
}

func New(host, port, user, pass string) Klap {
	authHash := hashAuth(user, pass)
	jar, _ := cookiejar.New(nil)
	return Klap{Host: host, Port: port, authHash: authHash[:], client: http.Client{Jar: jar}}
}

func (k Klap) baseUrl() string {
	return "http://" + k.Host + ":" + k.Port + "/app"
}

func (k *Klap) doHandshakeReq1(data []byte) ([]byte, error) {
	url := k.baseUrl() + "/handshake1"
	return k.doHandshakeReq(data, url)
}

func (k *Klap) doHandshakeReq2(data []byte) ([]byte, error) {
	url := k.baseUrl() + "/handshake2"
	return k.doHandshakeReq(data, url)
}

func (k *Klap) doHandshakeReq(data []byte, url string) ([]byte, error) {
	resp, err := k.client.Post(url, "application/octet-stream", bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, errors.New(resp.Status)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (k *Klap) handshake1() ([]byte, []byte, error) {
	localSeed := getNonce()

	body, err := k.doHandshakeReq1(localSeed)
	if err != nil {
		return nil, nil, err
	}
	remoteSeed := body[0:16]
	serverHash := body[16:]
	local_seed_auth_hash := hashHandshake1(localSeed, remoteSeed, k.authHash)

	if !slices.Equal(local_seed_auth_hash[:], serverHash) {
		return nil, nil, errors.New("handshake fail, hashes doesn't match")
	}
	return localSeed, remoteSeed, nil
}

func (k *Klap) handshake2(localSeed, remoteSeed []byte) error {
	payload := hashHandshake2(localSeed, remoteSeed, k.authHash)
	_, err := k.doHandshakeReq2(payload[:])
	return err
}

func (k *Klap) Handshake() error {
	localSeed, remoteSeed, err := k.handshake1()
	if err != nil {
		return err
	}
	return k.handshake2(localSeed, remoteSeed)
}
