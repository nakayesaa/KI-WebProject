package services

import (
	"errors"
	"mime/multipart"
	"project1/models"
	"project1/repositories"
)

var userIdNotFound = errors.New("User Invalid")

type fileService struct {
	fileRepo *repositories.FileRepository
}

func NewFileService(fRepo *repositories.FileRepository) *fileService {
	return &fileService{
		fileRepo: fRepo,
	}
}

func (s *fileService) Upload(userId uint, file *multipart.FileHeader) error {
	const MaxFileSize = 8 << 20

	if userId == 0 {
		return errors.New("invalid user ID")
	}

	if file == nil {
		return errors.New("file is required")
	}

	if file.Size > MaxFileSize {
		return errors.New("File size exceed 8MB limit")
	}

	newFile := models.File{
		UserID:       userId,
		OriginalName: file.Filename,
		OriginalSize: file.Size,
		OriginalType: file.Header.Get("Content-Type"),
	}

	return s.fileRepo.UploadFile(&newFile)
}
