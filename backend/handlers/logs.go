package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/config"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/database"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/models"
	"github.com/PhilHem/go-saml-reverse-proxy/frontend/templates"
)

type LogsResponse struct {
	Logs    []models.LogEntry `json:"logs"`
	Total   int64             `json:"total"`
	Page    int               `json:"page"`
	PerPage int               `json:"per_page"`
}

func LogsPage(w http.ResponseWriter, r *http.Request) {
	templates.Logs().Render(r.Context(), w)
}

func GetLogs(w http.ResponseWriter, r *http.Request) {
	var logs []models.LogEntry
	q := database.DB.Preload("User").Order("created_at DESC")

	// Pagination
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 50
	}

	// Filters
	if level := r.URL.Query().Get("level"); level != "" {
		q = q.Where("level = ?", level)
	}
	if source := r.URL.Query().Get("source"); source != "" {
		q = q.Where("source = ?", source)
	}
	if search := r.URL.Query().Get("search"); search != "" {
		q = q.Where("message LIKE ? OR data LIKE ?", "%"+search+"%", "%"+search+"%")
	}

	// Count total
	var total int64
	q.Model(&models.LogEntry{}).Count(&total)

	// Apply pagination
	offset := (page - 1) * perPage
	q.Offset(offset).Limit(perPage).Find(&logs)

	resp := LogsResponse{
		Logs:    logs,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func GetLogSources(w http.ResponseWriter, r *http.Request) {
	var sources []string
	database.DB.Model(&models.LogEntry{}).Distinct("source").Where("source != ''").Pluck("source", &sources)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sources)
}

type TimelinePoint struct {
	Time  string `json:"time"`
	Count int    `json:"count"`
}

type BulkDeleteRequest struct {
	IDs []uint `json:"ids"`
}

func DeleteLogs(w http.ResponseWriter, r *http.Request) {
	var req BulkDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if len(req.IDs) == 0 {
		http.Error(w, "No IDs provided", http.StatusBadRequest)
		return
	}

	result := database.DB.Delete(&models.LogEntry{}, req.IDs)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int64{"deleted": result.RowsAffected})
}

func GetLogTimeline(w http.ResponseWriter, r *http.Request) {
	timeRange := r.URL.Query().Get("range")
	if timeRange == "" {
		timeRange = "24h"
	}
	resolution := r.URL.Query().Get("resolution")

	// Calculate time window
	var hours int
	switch timeRange {
	case "1h":
		hours = 1
	case "6h":
		hours = 6
	case "24h":
		hours = 24
	case "7d":
		hours = 24 * 7
	case "30d":
		hours = 24 * 30
	default:
		hours = 24
	}

	// Auto resolution: aim for ~50-80 bars
	if resolution == "" || resolution == "auto" {
		switch {
		case hours <= 1:
			resolution = "1m"
		case hours <= 6:
			resolution = "5m"
		case hours <= 24:
			resolution = "15m"
		case hours <= 24*7:
			resolution = "1h"
		default:
			resolution = "1d"
		}
	}

	// Build SQL format string based on resolution
	var format string
	switch resolution {
	case "1m":
		format = "%Y-%m-%d %H:%M"
	case "5m":
		format = "strftime('%Y-%m-%d %H:', created_at) || printf('%02d', (cast(strftime('%M', created_at) as integer) / 5) * 5)"
	case "15m":
		format = "strftime('%Y-%m-%d %H:', created_at) || printf('%02d', (cast(strftime('%M', created_at) as integer) / 15) * 15)"
	case "1h":
		format = "%Y-%m-%d %H:00"
	case "1d":
		format = "%Y-%m-%d"
	default:
		format = "%Y-%m-%d %H:%M"
	}

	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	var dbResults []TimelinePoint
	query := database.DB.Model(&models.LogEntry{}).Where("created_at >= ?", cutoff)

	if resolution == "5m" || resolution == "15m" {
		query.Select(format + " as time, count(*) as count")
	} else {
		query.Select("strftime(?, created_at) as time, count(*) as count", format)
	}

	query.Group("time").Order("time ASC").Scan(&dbResults)

	// Fill in gaps with zero counts
	results := fillTimelineGaps(dbResults, cutoff, time.Now(), resolution)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func fillTimelineGaps(data []TimelinePoint, start, end time.Time, resolution string) []TimelinePoint {
	if len(data) == 0 {
		return generateEmptyTimeline(start, end, resolution)
	}

	// Build a map of existing data
	dataMap := make(map[string]int)
	for _, d := range data {
		dataMap[d.Time] = d.Count
	}

	// Generate all time slots
	var interval time.Duration
	var timeFormat string
	switch resolution {
	case "1m":
		interval = time.Minute
		timeFormat = "2006-01-02 15:04"
	case "5m":
		interval = 5 * time.Minute
		timeFormat = "2006-01-02 15:04"
	case "15m":
		interval = 15 * time.Minute
		timeFormat = "2006-01-02 15:04"
	case "1h":
		interval = time.Hour
		timeFormat = "2006-01-02 15:00"
	case "1d":
		interval = 24 * time.Hour
		timeFormat = "2006-01-02"
	default:
		interval = 15 * time.Minute
		timeFormat = "2006-01-02 15:04"
	}

	// Round start time down to interval
	start = start.Truncate(interval)

	var results []TimelinePoint
	for t := start; t.Before(end); t = t.Add(interval) {
		timeStr := t.Format(timeFormat)
		count := dataMap[timeStr]
		results = append(results, TimelinePoint{Time: timeStr, Count: count})
	}

	return results
}

func generateEmptyTimeline(start, end time.Time, resolution string) []TimelinePoint {
	var interval time.Duration
	var timeFormat string
	switch resolution {
	case "1m":
		interval = time.Minute
		timeFormat = "2006-01-02 15:04"
	case "5m":
		interval = 5 * time.Minute
		timeFormat = "2006-01-02 15:04"
	case "15m":
		interval = 15 * time.Minute
		timeFormat = "2006-01-02 15:04"
	case "1h":
		interval = time.Hour
		timeFormat = "2006-01-02 15:00"
	case "1d":
		interval = 24 * time.Hour
		timeFormat = "2006-01-02"
	default:
		interval = 15 * time.Minute
		timeFormat = "2006-01-02 15:04"
	}

	start = start.Truncate(interval)

	var results []TimelinePoint
	for t := start; t.Before(end); t = t.Add(interval) {
		results = append(results, TimelinePoint{Time: t.Format(timeFormat), Count: 0})
	}
	return results
}

type DBStats struct {
	UsedSizeBytes int64 `json:"used_size_bytes"`
	MaxSizeBytes  int64 `json:"max_size_bytes"`
}

func GetDBStats(w http.ResponseWriter, r *http.Request) {
	var pageCount, pageSize, freelistCount int64

	database.DB.Raw("PRAGMA page_count").Scan(&pageCount)
	database.DB.Raw("PRAGMA page_size").Scan(&pageSize)
	database.DB.Raw("PRAGMA freelist_count").Scan(&freelistCount)

	totalSize := pageCount * pageSize
	freeSize := freelistCount * pageSize
	usedSize := totalSize - freeSize

	stats := DBStats{
		UsedSizeBytes: usedSize,
		MaxSizeBytes:  config.C.Logs.MaxDBSize,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
