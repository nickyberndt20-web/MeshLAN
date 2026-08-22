package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

const aiEnvelopeVersion = 1

func generateX25519KeyPair() (privateText, publicText string, err error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(privateKey.Bytes()), base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()), nil
}

func validX25519PublicKey(value string) bool {
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(data) != 32 {
		return false
	}
	_, err = ecdh.X25519().NewPublicKey(data)
	return err == nil
}

func validX25519KeyPair(privateText, publicText string) bool {
	privateBytes, privateErr := base64.RawURLEncoding.DecodeString(privateText)
	publicBytes, publicErr := base64.RawURLEncoding.DecodeString(publicText)
	if privateErr != nil || publicErr != nil {
		return false
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	return err == nil && hmac.Equal(privateKey.PublicKey().Bytes(), publicBytes)
}

func aiEnvelopeKey(sharedSecret, aad []byte) []byte {
	extract := hmac.New(sha256.New, []byte("MeshLAN-AI-E2EE-v1"))
	_, _ = extract.Write(sharedSecret)
	pseudoRandomKey := extract.Sum(nil)
	expand := hmac.New(sha256.New, pseudoRandomKey)
	_, _ = expand.Write(aad)
	_, _ = expand.Write([]byte{1})
	return expand.Sum(nil)[:32]
}

func sealAIEnvelope(recipientPublicText string, plaintext, aad []byte) (AIEncryptedEnvelope, error) {
	publicBytes, err := base64.RawURLEncoding.DecodeString(recipientPublicText)
	if err != nil {
		return AIEncryptedEnvelope{}, errors.New("AI接收方公钥无效")
	}
	recipientPublic, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return AIEncryptedEnvelope{}, errors.New("AI接收方公钥无效")
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return AIEncryptedEnvelope{}, err
	}
	shared, err := ephemeral.ECDH(recipientPublic)
	if err != nil {
		return AIEncryptedEnvelope{}, err
	}
	block, err := aes.NewCipher(aiEnvelopeKey(shared, aad))
	if err != nil {
		return AIEncryptedEnvelope{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return AIEncryptedEnvelope{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return AIEncryptedEnvelope{}, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	return AIEncryptedEnvelope{Version: aiEnvelopeVersion, EphemeralPublicKey: base64.RawURLEncoding.EncodeToString(ephemeral.PublicKey().Bytes()), Nonce: base64.RawURLEncoding.EncodeToString(nonce), Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext)}, nil
}

func openAIEnvelope(privateText string, envelope AIEncryptedEnvelope, aad []byte) ([]byte, error) {
	if envelope.Version != aiEnvelopeVersion {
		return nil, errors.New("AI加密信封版本不受支持")
	}
	privateBytes, privateErr := base64.RawURLEncoding.DecodeString(privateText)
	publicBytes, publicErr := base64.RawURLEncoding.DecodeString(envelope.EphemeralPublicKey)
	nonce, nonceErr := base64.RawURLEncoding.DecodeString(envelope.Nonce)
	ciphertext, cipherErr := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if privateErr != nil || publicErr != nil || nonceErr != nil || cipherErr != nil {
		return nil, errors.New("AI加密信封格式无效")
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return nil, errors.New("AI解密私钥无效")
	}
	publicKey, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return nil, errors.New("AI临时公钥无效")
	}
	shared, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(aiEnvelopeKey(shared, aad))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != aead.NonceSize() {
		return nil, errors.New("AI加密信封Nonce无效")
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("AI加密信封认证失败")
	}
	return plaintext, nil
}
