package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

type ctxKey string

const userKey ctxKey = "user"

var db *gorm.DB

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

type RoleChange struct {
	ID   uint   `json:"id"`
	Role string `json:"role"`
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

func createNote(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Title string `json:"title"`
		Owner uint   `json:"owner"`
	}
	json.NewDecoder(r.Body).Decode(&in)
	note := Note{Title: in.Title, OwnerID: in.Owner}
	db.Create(&note)
	json.NewEncoder(w).Encode(note)
}

func exportUsers(w http.ResponseWriter, r *http.Request) {
	var users []User
	db.Find(&users)
	json.NewEncoder(w).Encode(users)
}

func deleteNote(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	db.Delete(&Note{}, id)
	w.WriteHeader(http.StatusNoContent)
}

func setRole(w http.ResponseWriter, r *http.Request) {
	var in RoleChange
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	db.Model(&User{}).Where("id = ?", in.ID).Update("role", in.Role)
	w.WriteHeader(http.StatusNoContent)
}

func login(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	password := r.FormValue("password")
	var u User
	if err := db.Where("email = ? AND password_hash = ?", email, password).First(&u).Error; err != nil {
		http.Error(w, "invalid", http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
}

func payWebhook(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	mac := hmac.New(sha256.New, []byte(os.Getenv("PAY_SECRET")))
	mac.Write(body)
	if !hmac.Equal(mac.Sum(nil), []byte(r.Header.Get("X-Pay-Signature"))) {
		log.Println("bad signature")
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
		URL string `json:"url"`
	}
	json.NewDecoder(r.Body).Decode(&in)
	resp, err := http.Get(in.URL)
	if err != nil {
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func upload(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "no file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	dst, _ := os.Create("uploads/" + header.Filename)
	io.Copy(dst, file)
	w.WriteHeader(http.StatusCreated)
}

func listItems(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	var items []Item
	db.Limit(limit).Find(&items)
	json.NewEncoder(w).Encode(items)
}
