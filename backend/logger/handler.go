package logger

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"time"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/config"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/models"

	"gorm.io/gorm"
)

type DBHandler struct {
	db          *gorm.DB
	jsonHandler slog.Handler
	attrs       []slog.Attr
}

func NewDBHandler(db *gorm.DB) *DBHandler {
	return &DBHandler{
		db:          db,
		jsonHandler: slog.NewJSONHandler(os.Stdout, nil),
		attrs:       []slog.Attr{},
	}
}

func extractUserID(v slog.Value) uint {
	switch v.Kind() {
	case slog.KindInt64:
		return uint(v.Int64())
	case slog.KindUint64:
		return uint(v.Uint64())
	default:
		return 0
	}
}

func (h *DBHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return true
}

func (h *DBHandler) Handle(ctx context.Context, r slog.Record) error {
	// Write to stdout
	_ = h.jsonHandler.Handle(ctx, r)

	// Extract attrs
	attrs := make(map[string]any)
	var source string
	var userID *uint

	// Include handler-level attrs
	for _, a := range h.attrs {
		switch a.Key {
		case "source":
			source = a.Value.String()
		case "user_id":
			id := extractUserID(a.Value)
			if id > 0 {
				userID = &id
			}
		default:
			attrs[a.Key] = a.Value.Any()
		}
	}

	// Include record attrs
	r.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "source":
			source = a.Value.String()
		case "user_id":
			id := extractUserID(a.Value)
			if id > 0 {
				userID = &id
			}
		default:
			attrs[a.Key] = a.Value.Any()
		}
		return true
	})

	var data string
	if len(attrs) > 0 {
		b, _ := json.Marshal(attrs)
		data = string(b)
	}

	entry := models.LogEntry{
		CreatedAt: time.Now(),
		Level:     r.Level.String(),
		Message:   r.Message,
		Source:    source,
		UserID:    userID,
		Data:      data,
	}

	return h.db.Create(&entry).Error
}

func (h *DBHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, len(h.attrs)+len(attrs))
	copy(newAttrs, h.attrs)
	copy(newAttrs[len(h.attrs):], attrs)
	return &DBHandler{
		db:          h.db,
		jsonHandler: h.jsonHandler,
		attrs:       newAttrs,
	}
}

func (h *DBHandler) WithGroup(name string) slog.Handler {
	return h
}

// CleanupOldLogs removes logs older than the specified duration and enforces max DB size
func CleanupOldLogs(db *gorm.DB, maxAge time.Duration) {
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		// Delete by age
		cutoff := time.Now().Add(-maxAge)
		db.Where("created_at < ?", cutoff).Delete(&models.LogEntry{})

		// Enforce max DB size
		enforceMaxDBSize(db)
	}
}

func enforceMaxDBSize(db *gorm.DB) {
	maxSize := config.C.Logs.MaxDBSize
	if maxSize <= 0 {
		return
	}

	var pageCount, pageSize, freelistCount int64
	db.Raw("PRAGMA page_count").Scan(&pageCount)
	db.Raw("PRAGMA page_size").Scan(&pageSize)
	db.Raw("PRAGMA freelist_count").Scan(&freelistCount)

	usedSize := (pageCount - freelistCount) * pageSize

	// Delete oldest 10% of logs if over limit
	if usedSize > maxSize {
		var count int64
		db.Model(&models.LogEntry{}).Count(&count)
		deleteCount := count / 10
		if deleteCount < 100 {
			deleteCount = 100
		}

		var oldestIDs []uint
		db.Model(&models.LogEntry{}).
			Order("created_at ASC").
			Limit(int(deleteCount)).
			Pluck("id", &oldestIDs)

		if len(oldestIDs) > 0 {
			db.Delete(&models.LogEntry{}, oldestIDs)
			db.Exec("VACUUM")
		}
	}
}

