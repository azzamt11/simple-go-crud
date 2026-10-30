package main

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

var (
	db        *sql.DB
	jwtSecret = []byte(getEnv("JWT_SECRET", "super-secret-default-key-change-in-prod"))
)

type contextKey string

const userContextKey contextKey = "authenticated_user_id"

type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password,omitempty"`
}

type AuthResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

type Post struct {
	ID           int    `json:"id"`
	Content      string `json:"content"`
	UserID       int    `json:"user_id"`
	UserName     string `json:"user_name"`
	ParentPostID *int   `json:"parent_post_id"`
	LikeCount    int    `json:"like_count"`
	IsLiked      bool   `json:"is_liked"`
}

type LikeRequest struct {
	PostID int `json:"post_id"`
}

type Claims struct {
	UserID int    `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

func main() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "gocrud.db"
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		log.Fatal(err)
	}

	var err error
	db, err = sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath)+"?_pragma=foreign_keys(1)")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}
	if _, err := db.Exec(schema); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	// Public Auth Endpoints
	mux.HandleFunc("/register", handleRegister)
	mux.HandleFunc("/login", handleLogin)

	// User Routes
	mux.Handle("/users", corsMiddleware(authMiddleware(http.HandlerFunc(handleUsers))))
	mux.Handle("/users/update", corsMiddleware(authMiddleware(http.HandlerFunc(updateUser))))
	mux.Handle("/users/delete", corsMiddleware(authMiddleware(http.HandlerFunc(deleteUser))))

	// Post Routes (Optional auth for GET so guest users can view posts, required auth for mutations)
	mux.Handle("/posts", corsMiddleware(optionalAuthMiddleware(http.HandlerFunc(handlePosts))))
	mux.Handle("/posts/delete", corsMiddleware(authMiddleware(http.HandlerFunc(deletePost))))

	// Like Routes (Protected)
	mux.Handle("/likes", corsMiddleware(authMiddleware(http.HandlerFunc(handleLikes))))
	mux.Handle("/likes/delete", corsMiddleware(authMiddleware(http.HandlerFunc(unlikePost))))

	fmt.Println("Server starting on :8080...")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// ----------------- Middleware -----------------

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, err := parseTokenFromRequest(r)
		if err != nil {
			http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func optionalAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			if userID, err := parseTokenFromRequest(r); err == nil {
				ctx := context.WithValue(r.Context(), userContextKey, userID)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func parseTokenFromRequest(r *http.Request) (