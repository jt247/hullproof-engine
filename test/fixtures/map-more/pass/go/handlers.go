package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

type ctxKey string

const userKey ctxKey = "user"
const maxUpload = 5 << 20

var db *gorm.DB
var validate = validator.New()
var allowedHosts = map[string]bool{"example.com": true}

type Note struct {
	ID      uint
	Title   string
	OwnerID uint
}

type User struct {
	ID           uint
	Email        string
	Role         string
	PasswordHash string
}

type Item struct {
	ID      uint
	OwnerID uint
	Name    string
}

type Account struct {
	ID   uint
	Paid bool
}

type NoteInput struct {
	Title string `json:"title" validate:"required,max=200"`
}

type RoleChange struct {
	ID   uint   `json:"id" validate:"required"`
	Role string `json:"role" validate:"oneof=member admin"`
}

func requireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		tok, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) { return []byte(os.Getenv("JWT_SECRET")), nil })
		if err != nil || !tok.Valid {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey, tok.Claims)))
	})
}

func requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var me User
		db.First(&me, currentUser(r))
		if me.Role != "admin" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func currentUser(r *http.Request) uint {
	claims, _ := r.Context().Value(userKey).(jwt.MapClaims)
	id, _ := strconv.Atoi(claims["sub"].(string))
	return uint(id)
}

func recordAudit(actor uint, action string, target uint) {
	db.Exec("INSERT INTO audit_log (actor, action, target) VALUES (?, ?, ?)", actor, action, target)
}

func createNote(w http.ResponseWriter, r *http.Request) {
	var in NoteInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || validate.Struct(&in) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	note := Note{Title: in.Title, OwnerID: currentUser(r)}
	db.Create(&note)
	json.NewEncoder(w).Encode(note)
}

func exportUsers(w http.ResponseWriter, r *http.Request) {
	var users []User
	db.Where("id = ?", currentUser(r)).Find(&users)
	json.NewEncoder(w).Encode(users)
}

func deleteNote(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	db.Where("id = ? AND owner_id = ?", id, currentUser(r)).Delete(&Note{})
	w.WriteHeader(http.StatusNoContent)
}

func setRole(w http.ResponseWriter, r *http.Request) {
	var in RoleChange
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || validate.Struct(&in) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	db.Model(&User{}).Where("id = ?", in.ID).Update("role", in.Role)
	recordAudit(currentUser(r), "set_role", in.ID)
	w.WriteHeader(http.StatusNoContent)
}

type LoginInput struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required"`
}

func login(w http.ResponseWriter, r *http.Request) {
	in := LoginInput{Email: r.FormValue("email"), Password: r.FormValue("password")}
	if validate.Struct(&in) != nil {
		http.Error(w, "invalid", http.StatusBadRequest)
		return
	}
	var u User
	if err := db.Where("email = ? AND password_hash = ?", in.Email, in.Password).First(&u).Error; err != nil {
		http.Error(w, "invalid", http.StatusUnauthorized)
		return
	}
	next := r.URL.Query().Get("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

func payWebhook(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	mac := hmac.New(sha256.New, []byte(os.Getenv("PAY_SECRET")))
	mac.Write(body)
	if !hmac.Equal(mac.Sum(nil), []byte(r.Header.Get("X-Pay-Signature"))) {
		http.Error(w, "bad signature", http.StatusBadRequest)
		return
	}
	var ev struct {
		Account uint `json:"account"`
	}
	json.Unmarshal(body, &ev)
	db.Model(&Account{}).Where("id = ?", ev.Account).Update("paid", true)
	w.WriteHeader(http.StatusOK)
}

func importPage(w http.ResponseWriter, r *http.Request) {
	var in struct {
		URL string `json:"url" validate:"required,url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || validate.Struct(&in) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	u, err := url.Parse(in.URL)
	if err != nil || !allowedHosts[u.Hostname()] {
		http.Error(w, "host not allowed", http.StatusBadRequest)
		return
	}
	resp, err := http.Get(in.URL)
	if err != nil {
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func upload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload)
	file, header, err := r.FormFile("file")
	if err != nil || header.Size > maxUpload {
		http.Error(w, "no file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	head := make([]byte, 512)
	file.Read(head)
	contentType := http.DetectContentType(head)
	if contentType != "image/png" && contentType != "image/jpeg" {
		http.Error(w, "type not allowed", http.StatusUnsupportedMediaType)
		return
	}
	dst, _ := os.Create("uploads/" + strconv.FormatInt(int64(currentUser(r)), 10))
	io.Copy(dst, file)
	w.WriteHeader(http.StatusCreated)
}

func listItems(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	limit = min(limit, 100)
	var items []Item
	db.Where("owner_id = ?", currentUser(r)).Limit(limit).Find(&items)
	json.NewEncoder(w).Encode(items)
}
