package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-contrib/cors"
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

// Encrypt encrypts data using AES-256-CBC with a random IV
func encrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate random IV
	iv, err := generateRandomBytes(aes.BlockSize)
	if err != nil {
		return nil, err
	}

	paddedData := pad(data)
	ciphertext := make([]byte, len(paddedData)+aes.BlockSize) // IV + ciphertext
	copy(ciphertext[:aes.BlockSize], iv)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], paddedData)

	return ciphertext, nil
}

// Decrypt decrypts data using AES-256-CBC
func decrypt(data, key []byte) ([]byte, error) {
	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	return unpad(plaintext)
}

// File handlers
func encryptFile(c *gin.Context) {
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

	if file.Size > 100*1024*1024 { // 50MB limit
		c.JSON(http.StatusBadRequest, gin.H{"error": "file too large"})
		return
	}

	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unable to open file"})
		return
	}
	defer src.Close()

	data, err := io.ReadAll(src)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unable to read file"})
		return
	}

	// Generate a random salt
	salt, err := generateRandomBytes(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	// Derive key from password and salt
	key, err := deriveKey([]byte(password), salt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "key derivation failed"})
		return
	}

	// Encrypt the data
	encryptedData, err := encrypt(data, key)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "encryption failed"})
		return
	}

	// Combine salt and encrypted data
	finalData := append(salt, encryptedData...)

	// Create temporary file with random name
	tempDir := os.TempDir()
	randomBytes, _ := generateRandomBytes(16)
	tempFile := filepath.Join(tempDir, hex.EncodeToString(randomBytes))
	if err := os.WriteFile(tempFile, finalData, 0600); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to save encrypted file"})
		return
	}
	defer os.Remove(tempFile)

	// Send encrypted file
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.enc", file.Filename))
	c.File(tempFile)
}

func decryptFile(c *gin.Context) {
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

	if file.Size > 50*1024*1024 { // 50MB limit
		c.JSON(http.StatusBadRequest, gin.H{"error": "file too large"})
		return
	}

	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unable to open file"})
		return
	}
	defer src.Close()

	data, err := io.ReadAll(src)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unable to read file"})
		return
	}

	if len(data) < 32 { // Salt size
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid encrypted file"})
		return
	}

	// Extract salt and derive key
	salt := data[:32]
	encryptedData := data[32:]

	key, err := deriveKey([]byte(password), salt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "key derivation failed"})
		return
	}

	// Decrypt the data
	decryptedData, err := decrypt(encryptedData, key)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "decryption failed"})
		return
	}

	// Create temporary file with random name
	tempDir := os.TempDir()
	randomBytes, _ := generateRandomBytes(16)
	tempFile := filepath.Join(tempDir, hex.EncodeToString(randomBytes))
	if err := os.WriteFile(tempFile, decryptedData, 0600); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to save decrypted file"})
		return
	}
	defer os.Remove(tempFile)

	// Send decrypted file
	originalFilename := strings.TrimSuffix(file.Filename, ".enc")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", originalFilename))
	c.File(tempFile)
}

func main() {
	// Set Gin to release mode
	gin.SetMode(gin.ReleaseMode)

	router := gin.Default()

	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"}, // Allow all origins
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "X-Requested-With", "X-Encryption-Password"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true, // Optionally allow credentials if needed
	}))

	// Set maximum multipart memory
	router.MaxMultipartMemory = 8 << 20 // 8 MiB

	// Register routes with new handler names
	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Secure File Upload/Download Service by babyo7_")
	})

	// Set maximum multipart memory
	router.MaxMultipartMemory = 8 << 20 // 8 MiB

	router.POST("/enc", encryptFile)
	router.POST("/dec", decryptFile)

	err := router.Run(":8000")
	if err != nil {
		fmt.Printf("Error starting server: %s\n", err)
		os.Exit(1)
	}
}
