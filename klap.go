package goklap

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
)

type Klap struct {
	host     string
	port     string
	client   http.Client
	authHash []byte
}

func New(host, port, user, pass string) Klap {
	authHash := hashAuth(user, pass)
	jar, _ := cookiejar.New(nil)
	return Klap{host: host, port: port, authHash: authHash[:], client: http.Client{Jar: jar}}
}

/*
Sends a request to the klap device.
Parameters:
  - target is the endpoint to send the request to, the url will be http://host:port/app/target?seq=seq.
    Seq is the sequence number of the request, handled by the library
  - msg is the message to send
  - params are the query parameters to send, seq will be added by the library

Returns:
  - The response from the device as a byte array
  - An error if something went wrong (connection, encryption, etc)
*/
func (k *Klap) Request(target, msg string, params url.Values) ([]byte, error) {
	localSeed, remoteSeed, err := k.handshake()
	if err != nil {
		return nil, err
	}
	chiper, err := newKlapChiper(localSeed, remoteSeed, k.authHash)
	if err != nil {
		return nil, err
	}
	encryptedPayload, err := chiper.encrypt([]byte(msg))
	if err != nil {
		return nil, err
	}
	if params == nil {
		params = url.Values{}
	}
	params.Add("seq", fmt.Sprintf("%d", chiper.seq))
	requestUrl := k.baseUrl() + "/" + target + "?" + params.Encode()
	encryptedResponse, err := k.doRequest(encryptedPayload, requestUrl)
	if err != nil {
		return nil, err
	}
	decryptedResponse, err := chiper.decrypt(encryptedResponse[32:])
	if err != nil {
		return nil, err
	}
	return decryptedResponse, nil
}

func getNonce() ([]byte, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
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

func (k Klap) baseUrl() string {
	return "http://" + k.host + ":" + k.port + "/app"
}

func (k *Klap) doHandshakeReq1(data []byte) ([]byte, error) {
	url := k.baseUrl() + "/handshake1"
	return k.doRequest(data, url)
}

func (k *Klap) doHandshakeReq2(data []byte) ([]byte, error) {
	url := k.baseUrl() + "/handshake2"
	return k.doRequest(data, url)
}

func (k *Klap) doRequest(payload []byte, url string) ([]byte, error) {
	resp, err := k.client.Post(url, "application/octet-stream", bytes.NewBuffer(payload))
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
	localSeed, err := getNonce()
	if err != nil {
		return nil, nil, err
	}
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

func (k *Klap) handshake() ([]byte, []byte, error) {
	newCookieJar, _ := cookiejar.New(nil)
	k.client.Jar = newCookieJar
	localSeed, remoteSeed, err := k.handshake1()
	if err != nil {
		return nil, nil, err
	}
	err = k.handshake2(localSeed, remoteSeed)
	if err != nil {
		return nil, nil, err
	}
	return localSeed, remoteSeed, nil
}
