package repositories

import (
	"errors"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func newDryRunFileRepository(t *testing.T) *FileRepository {
	t.Helper()
	// DryRun and disabled automatic ping ensure these tests never contact a DB.
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN: "host=127.0.0.1 port=1 user=unused dbname=unused sslmode=disable",
	}), &gorm.Config{
		DryRun:               true,
		DisableAutomaticPing: true,
		Logger:               logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sqlDB.Close() })
	return NewFileRepository(db)
}

func TestListByUserIDScopesAndOrdersQuery(t *testing.T) {
	repo := newDryRunFileRepository(t)
	var query string
	var args []any
	if err := repo.DB.Callback().Query().After("gorm:query").Register("capture_list_query", func(db *gorm.DB) {
		query = db.Statement.SQL.String()
		args = append([]any(nil), db.Statement.Vars...)
	}); err != nil {
		t.Fatal(err)
	}

	files, err := repo.ListByUserID(7)
	if err != nil || files == nil || len(files) != 0 {
		t.Fatalf("expected empty initialized result in dry run: %v, %v", files, err)
	}
	if query != `SELECT * FROM "files" WHERE user_id = $1 ORDER BY id DESC` {
		t.Fatalf("unexpected owner-scoped ordered SQL: %s", query)
	}
	if len(args) != 1 || args[0] != uint(7) {
		t.Fatalf("query must bind the authenticated owner's ID: %v", args)
	}
}

func TestListByUserIDPropagatesQueryError(t *testing.T) {
	repo := newDryRunFileRepository(t)
	queryError := errors.New("query failed")
	if err := repo.DB.Callback().Query().Before("gorm:query").Register("fail_list_query", func(db *gorm.DB) {
		db.AddError(queryError)
	}); err != nil {
		t.Fatal(err)
	}
	files, err := repo.ListByUserID(7)
	if !errors.Is(err, queryError) || files != nil {
		t.Fatalf("expected query error without partial results: %v, %v", files, err)
	}
}
