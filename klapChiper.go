package goklap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

type klapChiper struct {
	iv, sig      []byte
	blockChipher cipher.Block
	seq          int
}

func newKlapChiper(localSeed, remoteSeed, userHash []byte) (klapChiper, error) {
	rv := klapChiper{}
	key := keyDerive(localSeed, remoteSeed, userHash)
	blockChipher, err := aes.NewCipher(key)
	if err != nil {
		return rv, err
	}
	rv.blockChipher = blockChipher
	rv.iv, rv.seq = ivDerive(localSeed, remoteSeed, userHash)
	rv.sig = sigDerive(localSeed, remoteSeed, userHash)

	return rv, nil
}

func (k *klapChiper) encrypt(msg []byte) ([]byte, error) {
	k.seq++
	cbc := cipher.NewCBCEncrypter(k.blockChipher, getIvCbc(k.iv, k.seq))
	padded, err := pkcs7pad(msg, k.blockChipher.BlockSize())
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(padded))
	cbc.CryptBlocks(ciphertext, padded)

	ivArr := make([]byte, 4)
	binary.BigEndian.PutUint32(ivArr, uint32(k.seq))
	signature := sha256.Sum256(append(append(k.sig, ivArr...), ciphertext...))

	return append(signature[:], ciphertext...), nil
}

func (k *klapChiper) decrypt(encrypted []byte) ([]byte, error) {

	cbc := cipher.NewCBCDecrypter(k.blockChipher, getIvCbc(k.iv, k.seq))
	decrypted := make([]byte, len(encrypted))
	cbc.CryptBlocks(decrypted, encrypted)
	d, err := pkcs7Unpad(decrypted)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func keyDerive(localSeed, remoteSeed, userHash []byte) []byte {
	payload := append(append(append([]byte("lsk"), localSeed...), remoteSeed...), userHash...)
	rv := sha256.Sum256(payload)
	return rv[:16]
}

func ivDerive(localSeed, remoteSeed, userHash []byte) ([]byte, int) {
	payload := append(append(append([]byte("iv"), localSeed...), remoteSeed...), userHash...)
	fullIv := sha256.Sum256(payload)
	seq := int(big.NewInt(0).SetBytes(fullIv[32-4:]).Uint64())
	return fullIv[:12], seq
}

func sigDerive(localSeed, remoteSeed, userHash []byte) []byte {
	payload := append(append(append([]byte("ldk"), localSeed...), remoteSeed...), userHash...)
	rv := sha256.Sum256(payload)
	return rv[:28]
}

func getIvCbc(iv []byte, seq int) []byte {
	rv := make([]byte, 0, len(iv)+4)
	rv = append(rv, iv...)
	return binary.BigEndian.AppendUint32(rv, uint32(seq))
}
