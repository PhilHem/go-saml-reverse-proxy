package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"todo-app/backend/database"
	"todo-app/backend/models"
	"todo-app/frontend/templates"
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
	interval := r.URL.Query().Get("interval")
	if interval == "" {
		interval = "hour"
	}

	var format string
	switch interval {
	case "minute":
		format = "%Y-%m-%d %H:%M"
	case "hour":
		format = "%Y-%m-%d %H:00"
	case "day":
		format = "%Y-%m-%d"
	default:
		format = "%Y-%m-%d %H:00"
	}

	var results []TimelinePoint
	database.DB.Model(&models.LogEntry{}).
		Select("strftime(?, created_at) as time, count(*) as count", format).
		Group("time").
		Order("time ASC").
		Limit(100).
		Scan(&results)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}
