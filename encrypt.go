// Copyright (c) 2013 - Alex Yu <alex@alexyu.se>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can
// be found in the LICENSE file.

// Package encrypt provides encrypt and decrypt functions for byte blocks with AES.
//
// From stack overflow: http://stackoverflow.com/questions/18817336/golang-encrypting-a-string-with-aes-and-base64
package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
)

// Encrypt with specified key (32 bytes)
func Encrypt(key, text []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	b := EncodeBase64(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext
}

// Decrypt with specified key (32 bytes)
func Decrypt(key, text []byte) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if len(text) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	return string(DecodeBase64(string(text)))
}

func EncodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func DecodeBase64(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func Sha1(b []byte) string {
	hash := sha1.New()
	hash.Write(b)
	return fmt.Sprintf("%x", hash.Sum(nil))
}
