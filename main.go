package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/scrypt"
)

// Configuration constants
const (
	ScryptN      = 32768
	ScryptR      = 8
	ScryptP      = 1
	ScryptKeyLen = 32
)

// KeyDerivation derives an encryption key from a password using scrypt
func deriveKey(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, ScryptN, ScryptR, ScryptP, ScryptKeyLen)
}

// GenerateRandomBytes generates cryptographically secure random bytes
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// Pad implements PKCS7 padding
func pad(data []byte) []byte {
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// Unpad removes PKCS7 padding
func unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("empty data")
	}

	padding := int(data[length-1])
	if padding > aes.BlockSize || padding == 0 {
		return nil, errors.New("invalid padding")
	}

	// Verify padding
	for i := length - padding; i < length; i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("invalid padding")
		}
	}

	return data[:length-padding], nil
}

// uploadEncrypt handles file encryption
func uploadEncrypt(c *gin.Context) {
	password := c.GetHeader("X-Encryption-Password")
	if password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "encryption password required"})
		return
	}

	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file upload failed"})
		return
	}

	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unable to open file"})
		return
	}
	defer src.Close()

	// Generate salt and derive key
	salt, err := generateRandomBytes(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	key, err := deriveKey([]byte(password), salt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "key derivation failed"})
		return
	}

	// Set headers for streaming response
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.enc", file.Filename))
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Transfer-Encoding", "chunked")

	writer := c.Writer

	// Write the salt first
	if _, err := writer.Write(salt); err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	// Generate random IV
	iv, err := generateRandomBytes(aes.BlockSize)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	// Write the IV
	if _, err := writer.Write(iv); err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	// Create the cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	// Create CBC encrypter
	mode := cipher.NewCBCEncrypter(block, iv)

	// Create buffer for reading
	buffer := make([]byte, 1024*1024) // 1MB buffer
	var accumulator []byte

	for {
		n, err := src.Read(buffer)
		if err != nil && err != io.EOF {
			c.Status(http.StatusInternalServerError)
			return
		}

		if n > 0 {
			accumulator = append(accumulator, buffer[:n]...)
		}

		// Process full blocks, leaving any partial block in accumulator
		for len(accumulator) >= aes.BlockSize {
			chunk := accumulator[:aes.BlockSize]
			encrypted := make([]byte, aes.BlockSize)
			mode.CryptBlocks(encrypted, chunk)
			if _, err := writer.Write(encrypted); err != nil {
				c.Status(http.StatusInternalServerError)
				return
			}
			accumulator = accumulator[aes.BlockSize:]
		}

		if err == io.EOF {
			// Pad and encrypt the final block
			if len(accumulator) > 0 || len(accumulator) == 0 {
				paddedData := pad(accumulator)
				encrypted := make([]byte, len(paddedData))
				mode.CryptBlocks(encrypted, paddedData)
				if _, err := writer.Write(encrypted); err != nil {
					c.Status(http.StatusInternalServerError)
					return
				}
			}
			break
		}
	}

	writer.Flush()
}

// uploadDecrypt handles file decryption
func uploadDecrypt(c *gin.Context) {
	password := c.GetHeader("X-Encryption-Password")
	if password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "decryption password required"})
		return
	}

	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file upload failed"})
		return
	}

	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unable to open file"})
		return
	}
	defer src.Close()

	// Read salt
	salt := make([]byte, 32)
	if _, err := io.ReadFull(src, salt); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid encrypted file"})
		return
	}

	// Derive key
	key, err := deriveKey([]byte(password), salt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "key derivation failed"})
		return
	}

	// Read IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(src, iv); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid encrypted file"})
		return
	}

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	// Create CBC decrypter
	mode := cipher.NewCBCDecrypter(block, iv)

	// Set headers for streaming response
	originalFilename := strings.TrimSuffix(file.Filename, ".enc")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", originalFilename))
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Transfer-Encoding", "chunked")

	writer := c.Writer

	// Read the entire encrypted content
	encryptedData, err := io.ReadAll(src)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	// The data must be a multiple of the block size
	if len(encryptedData)%aes.BlockSize != 0 {
		c.Status(http.StatusBadRequest)
		return
	}

	// Decrypt all the data
	decrypted := make([]byte, len(encryptedData))
	mode.CryptBlocks(decrypted, encryptedData)

	// Remove padding from the decrypted data
	unpadded, err := unpad(decrypted)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	// Write the decrypted and unpadded data
	if _, err := writer.Write(unpadded); err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	writer.Flush()
}

func main() {
	// Set Gin to release mode
	gin.SetMode(gin.ReleaseMode)

	router := gin.Default()

	// Set maximum multipart memory
	router.MaxMultipartMemory = 8 << 20 // 8 MiB

	// Register routes with new handler names
	router.POST("/enc", uploadEncrypt)
	router.POST("/dec", uploadDecrypt)

	// Start server with TLS
	srv := &http.Server{
		Addr:    ":8443",
		Handler: router,
	}

	fmt.Println("Starting secure server on :8443...")
	if err := srv.ListenAndServe(); err != nil {
		fmt.Printf("Server error: %v\n", err)
		os.Exit(1)
	}
}
