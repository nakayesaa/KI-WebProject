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

func (r *FileRepository) ListByUserID(userID uint) ([]models.File, error) {
	files := make([]models.File, 0)
	if err := r.DB.Where("user_id = ?", userID).Order("id DESC").Find(&files).Error; err != nil {
		return nil, err
	}
	return files, nil
}

func (r *FileRepository) FindByIDAndUserID(fileID, userID uint) (*models.File, error) {
	var file models.File
	if err := r.DB.Where("id = ? AND user_id = ?", fileID, userID).First(&file).Error; err != nil {
		return nil, err
	}
	return &file, nil
}

func (r *FileRepository) UpdateAESDecryptTime(fileID, userID uint, durationNS int64) error {
	result := r.DB.Model(&models.File{}).
		Where("id = ? AND user_id = ?", fileID, userID).
		Update("aes_decrypt_time_ns", durationNS)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}
