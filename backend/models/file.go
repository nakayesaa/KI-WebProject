package models

type File struct {
	ID     uint `gorm:"primaryKey"`
	UserID uint `gorm:"not null;index"`

	OriginalName string `gorm:"not null"`
	OriginalSize int64  `gorm:"not null"`
	OriginalType string `gorm:"not null"`

	AESPath string
	RC4Path string
	DESPath string

	AESEncryptTimeNS int64 `gorm:"column:aes_encrypt_time_ns;not null;default:0"`
	AESDecryptTimeNS int64 `gorm:"column:aes_decrypt_time_ns;not null;default:0"`
}
