package ecb_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/mi1eschen/go-utils/pkg/cipher/ecb"
	"github.com/stretchr/testify/assert"
)

func TestAESECBPKCS5PADDING(t *testing.T) {
	plaintext := "920289f3-3f5f-4827-b491-b02772f88d4b"

	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatal(err)
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := encrypt(cipher, plaintext)

	got, err := decrypt(cipher, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, plaintext, got)
}

// AES/ECB/PCKS5PADDING
func encrypt(block cipher.Block, plaintext string) string {
	ecb := ecb.NewECBEncrypter(block)
	content := []byte(plaintext)
	content = pkcs5Padding(content, block.BlockSize())
	des := make([]byte, len(content))
	ecb.CryptBlocks(des, content)
	return base64.StdEncoding.EncodeToString(des)
}

func pkcs5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func decrypt(block cipher.Block, ciphertext string) (string, error) {
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	blockMode := ecb.NewECBDecrypter(block)
	origData := make([]byte, len(ciphertextBytes))
	blockMode.CryptBlocks(origData, ciphertextBytes)
	origData = pkcs5Trimming(origData)
	return string(origData), nil
}

func pkcs5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}
