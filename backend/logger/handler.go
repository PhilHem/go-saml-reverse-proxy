package logger

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"time"
	"todo-app/backend/models"

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

// CleanupOldLogs removes logs older than the specified duration
func CleanupOldLogs(db *gorm.DB, maxAge time.Duration) {
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		cutoff := time.Now().Add(-maxAge)
		db.Where("created_at < ?", cutoff).Delete(&models.LogEntry{})
	}
}

