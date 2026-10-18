package repositories

import (
	"project1/models"

	"gorm.io/gorm"
)

type FileRepository struct {
	DB *gorm.DB
}

func NewFileRepository(db *gorm.DB) *FileRepository {
	return &FileRepository{DB: db}
}

func (r *FileRepository) UploadFile(file *models.File) error {
	return r.DB.Create(file).Error
}
