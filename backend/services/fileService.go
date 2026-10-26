package services

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
	"time"

	"project1/models"
	"project1/utils"

	"gorm.io/gorm"
)

const (
	MaxFileSize      = 8 << 20
	AESFileAlgorithm = "AES-128-CBC-HMAC-SHA256"
	// Envelope overhead: magic, IV, one full padding block, and SHA-256 MAC.
	maxEncryptedFileSize = MaxFileSize + 4 + 16 + 16 + 32
)

var (
	ErrInvalidUser   = errors.New("invalid user ID")
	ErrFileRequired  = errors.New("file is required")
	ErrFileTooLarge  = errors.New("file size exceeds 8 MiB limit")
	ErrFileNotFound  = errors.New("file not found")
	ErrFileIntegrity = errors.New("encrypted file is unavailable or failed integrity verification")
)

type fileRepository interface {
	UploadFile(*models.File) error
	FindByIDAndUserID(fileID, userID uint) (*models.File, error)
	UpdateAESDecryptTime(fileID, userID uint, durationNS int64) error
}

type FileService struct {
	fileRepo   fileRepository
	storageDir string
	key        [utils.AESFileKeySize]byte
}

func NewFileService(fRepo fileRepository, storageDir string, key [utils.AESFileKeySize]byte) (*FileService, error) {
	if storageDir == "" {
		return nil, errors.New("file storage directory is required")
	}
	absoluteDir, err := filepath.Abs(storageDir)
	if err != nil {
		return nil, fmt.Errorf("resolve file storage directory: %w", err)
	}
	if err := os.MkdirAll(absoluteDir, 0700); err != nil {
		return nil, fmt.Errorf("create file storage directory: %w", err)
	}
	return &FileService{fileRepo: fRepo, storageDir: absoluteDir, key: key}, nil
}

func (s *FileService) Upload(userID uint, file *multipart.FileHeader) (*models.File, error) {
	if userID == 0 {
		return nil, ErrInvalidUser
	}
	if file == nil {
		return nil, ErrFileRequired
	}
	if file.Size > MaxFileSize {
		return nil, ErrFileTooLarge
	}

	source, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("open uploaded file: %w", err)
	}
	defer source.Close()

	// Do not trust the declared multipart size; bound the actual bytes read too.
	plaintext, err := io.ReadAll(io.LimitReader(source, MaxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read uploaded file: %w", err)
	}
	if len(plaintext) > MaxFileSize {
		return nil, ErrFileTooLarge
	}

	start := time.Now()
	encrypted, err := utils.EncryptAESFile(plaintext, s.key)
	encryptTime := time.Since(start).Nanoseconds()
	if err != nil {
		return nil, fmt.Errorf("encrypt uploaded file: %w", err)
	}

	// Measure an actual decryption and verify the round trip before persisting.
	start = time.Now()
	decrypted, err := utils.DecryptAESFile(encrypted, s.key)
	decryptTime := time.Since(start).Nanoseconds()
	if err != nil || !bytes.Equal(plaintext, decrypted) {
		return nil, ErrFileIntegrity
	}

	// A generated name prevents overwrites and avoids using user-controlled paths.
	stored, err := os.CreateTemp(s.storageDir, "aes-*.bin")
	if err != nil {
		return nil, fmt.Errorf("create encrypted file: %w", err)
	}
	persisted := false
	defer func() {
		stored.Close()
		if !persisted {
			os.Remove(stored.Name())
		}
	}()
	if _, err := stored.Write(encrypted); err != nil {
		return nil, fmt.Errorf("write encrypted file: %w", err)
	}
	if err := stored.Close(); err != nil {
		return nil, fmt.Errorf("close encrypted file: %w", err)
	}

	newFile := &models.File{
		UserID:           userID,
		OriginalName:     filepath.Base(strings.ReplaceAll(file.Filename, "\\", "/")),
		OriginalSize:     int64(len(plaintext)),
		OriginalType:     file.Header.Get("Content-Type"),
		AESPath:          stored.Name(),
		AESEncryptTimeNS: encryptTime,
		AESDecryptTimeNS: decryptTime,
	}
	if err := s.fileRepo.UploadFile(newFile); err != nil {
		return nil, fmt.Errorf("save file metadata: %w", err)
	}
	persisted = true
	return newFile, nil
}

func (s *FileService) FindByID(userID, fileID uint) (*models.File, error) {
	if userID == 0 {
		return nil, ErrInvalidUser
	}
	file, err := s.fileRepo.FindByIDAndUserID(fileID, userID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrFileNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find file: %w", err)
	}
	return file, nil
}

func (s *FileService) Decrypt(userID, fileID uint) (*models.File, []byte, error) {
	file, err := s.FindByID(userID, fileID)
	if err != nil {
		return nil, nil, err
	}

	// Only generated files inside the configured storage directory can be opened.
	relative, err := filepath.Rel(s.storageDir, file.AESPath)
	if err != nil || relative == "." || filepath.Base(relative) != relative || !strings.HasPrefix(relative, "aes-") {
		return nil, nil, ErrFileIntegrity
	}
	stored, err := os.Open(file.AESPath)
	if err != nil {
		return nil, nil, ErrFileIntegrity
	}
	defer stored.Close()
	encrypted, err := io.ReadAll(io.LimitReader(stored, maxEncryptedFileSize+1))
	if err != nil || len(encrypted) > maxEncryptedFileSize {
		return nil, nil, ErrFileIntegrity
	}

	start := time.Now()
	plaintext, err := utils.DecryptAESFile(encrypted, s.key)
	duration := time.Since(start).Nanoseconds()
	if err != nil || int64(len(plaintext)) != file.OriginalSize {
		return nil, nil, ErrFileIntegrity
	}
	if err := s.fileRepo.UpdateAESDecryptTime(file.ID, userID, duration); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, ErrFileNotFound
		}
		return nil, nil, fmt.Errorf("save decryption duration: %w", err)
	}
	file.AESDecryptTimeNS = duration
	return file, plaintext, nil
}
