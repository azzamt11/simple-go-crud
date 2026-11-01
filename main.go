package main

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
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
	Phone    string `json:"phone,omitempty"`
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

type Moment struct {
	ID          int      `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	ImageURLs   []string `json:"imageUrls"`
	Tag         string   `json:"tag"`
	UserID      *int     `json:"userId,omitempty"`
	CreatedAt   string   `json:"createdAt"`
	UpdatedAt   string   `json:"updatedAt"`
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
	if err := ensurePhoneColumn(); err != nil {
		log.Fatal(err)
	}
	if err := ensureMomentsTable(); err != nil {
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

	// Moment and file routes
	mux.Handle("/moments", corsMiddleware(http.HandlerFunc(handleMoments)))
	mux.Handle("/moment", corsMiddleware(http.HandlerFunc(handleMoment)))
	mux.Handle("/moment/", corsMiddleware(http.HandlerFunc(handleMoment)))
	mux.Handle("/file/upload", corsMiddleware(authMiddleware(http.HandlerFunc(handleFileUpload))))
	mux.Handle("/files/", corsMiddleware(http.HandlerFunc(handleFileDownload)))

	fmt.Println("Server starting on :8080...")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func ensureMomentsTable() error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS moments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		description TEXT NOT NULL DEFAULT '',
		image_urls TEXT NOT NULL DEFAULT '[]',
		tag TEXT NOT NULL DEFAULT '',
		user_id INTEGER,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
	)`)
	return err
}

func ensurePhoneColumn() error {
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('users') WHERE name = 'phone'").Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		if _, err := db.Exec("ALTER TABLE users ADD COLUMN phone TEXT"); err != nil {
			return err
		}
		_, err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone ON users(phone) WHERE phone IS NOT NULL")
		return err
	}
	return nil
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
		authHeaderPresent := r.Header.Get("Authorization") != ""
		if authHeaderPresent {
			if userID, err := parseTokenFromRequest(r); err == nil {
				ctx := context.WithValue(r.Context(), userContextKey, userID)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			} else {
				log.Printf("optional auth failed: method=%s path=%s error=%v", r.Method, r.URL.RequestURI(), err)
			}
		} else if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
			log.Printf("optional auth missing for mutation: method=%s path=%s", r.Method, r.URL.RequestURI())
		}
		next.ServeHTTP(w, r)
	})
}

func parseTokenFromRequest(r *http.Request) (int, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return 0, errors.New("missing authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return 0, errors.New("invalid authorization header format")
	}

	tokenStr := parts[1]
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return 0, errors.New("invalid or expired token")
	}

	return claims.UserID, nil
}

func getUserIDFromContext(ctx context.Context) (int, bool) {
	val := ctx.Value(userContextKey)
	if val == nil {
		return 0, false
	}
	id, ok := val.(int)
	return id, ok
}

// ----------------- Auth Handlers -----------------

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req User
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" || req.Name == "" {
		http.Error(w, "Name, email, and password are required", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	res, err := db.Exec("INSERT INTO users(name, email, phone, password_hash) VALUES(?, ?, ?, ?)", req.Name, req.Email, nullablePhone(req.Phone), string(hashedPassword))
	if err != nil {
		http.Error(w, "Email might already be taken or DB error occurred", http.StatusBadRequest)
		return
	}

	newID, _ := res.LastInsertId()
	req.ID = int(newID)
	req.Password = ""

	token, err := generateJWT(req.ID, req.Email)
	if err != nil {
		http.Error(w, "Failed to generate session token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(AuthResponse{Token: token, User: req})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Phone    string `json:"phone"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.Email == "" && req.Phone == "") || req.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	var user User
	var passwordHash string
	identifier := req.Email
	query := "SELECT id, name, email, COALESCE(phone, ''), password_hash FROM users WHERE email = ?"
	if req.Phone != "" {
		identifier = req.Phone
		query = "SELECT id, name, email, COALESCE(phone, ''), password_hash FROM users WHERE phone = ?"
	}
	err := db.QueryRow(query, identifier).
		Scan(&user.ID, &user.Name, &user.Email, &user.Phone, &passwordHash)
	if err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	token, err := generateJWT(user.ID, user.Email)
	if err != nil {
		http.Error(w, "Failed to create session token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{Token: token, User: user})
}

func nullablePhone(phone string) interface{} {
	phone = strings.TrimSpace(phone)
	if phone == "" {
		return nil
	}
	return phone
}

func generateJWT(userID int, email string) (string, error) {
	claims := Claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(72 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// ----------------- User Handlers -----------------

func handleUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		rows, err := db.Query("SELECT id, name, email FROM users")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		users := make([]User, 0)
		for rows.Next() {
			var u User
			if err := rows.Scan(&u.ID, &u.Name, &u.Email); err == nil {
				users = append(users, u)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)
	}
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	currentUserID, _ := getUserIDFromContext(r.Context())

	var u User
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	_, err := db.Exec("UPDATE users SET name = ?, email = ? WHERE id = ?", u.Name, u.Email, currentUserID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	currentUserID, _ := getUserIDFromContext(r.Context())

	_, err := db.Exec("DELETE FROM users WHERE id = ?", currentUserID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ----------------- Post Handlers -----------------

func handlePosts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		parentPostIDStr := r.URL.Query().Get("parentPostId")
		currentUserID, _ := getUserIDFromContext(r.Context()) // 0 if not logged in

		baseQuery := `
			SELECT 
				p.id, 
				p.content, 
				p.parent_post_id, 
				p.user_id,
				u.name as user_name,
				COUNT(l.post_id) as like_count,
				(SELECT COUNT(*) FROM post_likes WHERE post_id = p.id AND user_id = ?) as is_liked
			FROM posts p 
			LEFT JOIN post_likes l ON p.id = l.post_id 
			LEFT JOIN users u ON p.user_id = u.id `

		var rows *sql.Rows
		var err error

		if parentPostIDStr != "" {
			query := baseQuery + "WHERE p.parent_post_id = ? GROUP BY p.id, u.name ORDER BY p.created_at DESC"
			rows, err = db.Query(query, currentUserID, parentPostIDStr)
		} else {
			query := baseQuery + "WHERE p.parent_post_id IS NULL GROUP BY p.id, u.name ORDER BY p.created_at DESC"
			rows, err = db.Query(query, currentUserID)
		}

		if err != nil {
			log.Printf("Query error: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		posts := make([]Post, 0)
		for rows.Next() {
			var p Post
			var isLikedInt int
			err := rows.Scan(&p.ID, &p.Content, &p.ParentPostID, &p.UserID, &p.UserName, &p.LikeCount, &isLikedInt)
			if err != nil {
				log.Printf("Scan error: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			p.IsLiked = isLikedInt > 0
			posts = append(posts, p)
		}

		json.NewEncoder(w).Encode(posts)

	case http.MethodPost:
		log.Printf("reply request received: method=%s path=%s remote=%s", r.Method, r.URL.RequestURI(), r.RemoteAddr)
		currentUserID, ok := getUserIDFromContext(r.Context())
		if !ok {
			log.Printf("reply rejected: missing authenticated user")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		log.Printf("reply authenticated: user_id=%d", currentUserID)

		var p Post
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			log.Printf("reply decode failed: user_id=%d error=%v", currentUserID, err)
			http.Error(w, "Invalid input", http.StatusBadRequest)
			return
		}
		log.Printf("reply payload decoded: user_id=%d parent_post_id=%v content_length=%d", currentUserID, p.ParentPostID, len(p.Content))

		if strings.TrimSpace(p.Content) == "" {
			log.Printf("reply rejected: user_id=%d empty content", currentUserID)
			http.Error(w, "Content is required", http.StatusBadRequest)
			return
		}

		result, err := db.Exec("INSERT INTO posts(content, user_id, parent_post_id) VALUES(?, ?, ?)",
			p.Content, currentUserID, p.ParentPostID)
		if err != nil {
			log.Printf("reply insert failed: user_id=%d parent_post_id=%v error=%v", currentUserID, p.ParentPostID, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		newID, err := result.LastInsertId()
		if err != nil {
			log.Printf("reply insert succeeded but reading id failed: user_id=%d error=%v", currentUserID, err)
			http.Error(w, "Reply created but failed to read its id", http.StatusInternalServerError)
			return
		}
		log.Printf("reply created: id=%d user_id=%d parent_post_id=%v", newID, currentUserID, p.ParentPostID)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{"message": "Post created", "id": newID})

	case http.MethodPut:
		currentUserID, ok := getUserIDFromContext(r.Context())
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var p Post
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "Invalid input", http.StatusBadRequest)
			return
		}
		if p.ID == 0 || strings.TrimSpace(p.Content) == "" {
			http.Error(w, "Post ID and content are required", http.StatusBadRequest)
			return
		}

		// Verify author ownership
		result, err := db.Exec("UPDATE posts SET content = ? WHERE id = ? AND user_id = ?", p.Content, p.ID, currentUserID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			http.Error(w, "Post not found or unauthorized to update", http.StatusForbidden)
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"message": "Post updated"})
	}
}

func deletePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	currentUserID, ok := getUserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id parameter is required", http.StatusBadRequest)
		return
	}

	result, err := db.Exec("DELETE FROM posts WHERE id = ? AND user_id = ?", id, currentUserID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Post not found or unauthorized to delete", http.StatusForbidden)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ----------------- Like Handlers -----------------

func handleLikes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	currentUserID, ok := getUserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req LikeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PostID == 0 {
		http.Error(w, "Invalid post_id", http.StatusBadRequest)
		return
	}

	_, err := db.Exec("INSERT OR IGNORE INTO post_likes(post_id, user_id) VALUES(?, ?)", req.PostID, currentUserID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func unlikePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	currentUserID, ok := getUserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	postIDStr := r.URL.Query().Get("post_id")
	postID, err := strconv.Atoi(postIDStr)
	if err != nil || postID == 0 {
		http.Error(w, "Valid post_id query parameter required", http.StatusBadRequest)
		return
	}

	db.Exec("DELETE FROM post_likes WHERE post_id = ? AND user_id = ?", postID, currentUserID)
	w.WriteHeader(http.StatusNoContent)
}

// ----------------- Moment Handlers -----------------

type momentRequest struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	ImageURLs   []string `json:"imageUrls"`
	Tag         string   `json:"tag"`
}

func handleMoments(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rows, err := db.Query(`SELECT id, title, description, image_urls, tag, user_id, created_at, updated_at
		FROM moments ORDER BY created_at DESC, id DESC`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	moments := make([]Moment, 0)
	for rows.Next() {
		moment, err := scanMoment(rows)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		moments = append(moments, moment)
	}
	writeJSON(w, http.StatusOK, moments)
}

func handleMoment(w http.ResponseWriter, r *http.Request) {
	pathID := strings.TrimPrefix(strings.Trim(r.URL.Path, "/"), "moment/")
	id, err := strconv.Atoi(pathID)
	if r.URL.Path == "/moment" && r.Method == http.MethodPost {
		id = 0
		err = nil
	}
	if err != nil || (id < 1 && !(r.URL.Path == "/moment" && r.Method == http.MethodPost)) {
		http.Error(w, "Valid moment id is required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		moment, err := getMoment(id)
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "Moment not found", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, moment)
	case http.MethodPost, http.MethodPut:
		var req momentRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		req.Title = strings.TrimSpace(req.Title)
		if req.Title == "" {
			http.Error(w, "title is required", http.StatusBadRequest)
			return
		}
		userID, _ := getUserIDFromContext(r.Context())
		images, _ := json.Marshal(req.ImageURLs)
		var result sql.Result
		if r.Method == http.MethodPost {
			result, err = db.Exec(`INSERT INTO moments(title, description, image_urls, tag, user_id, updated_at)
				VALUES(?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`, req.Title, req.Description, string(images), req.Tag, userID)
		} else {
			result, err = db.Exec(`UPDATE moments SET title=?, description=?, image_urls=?, tag=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
				req.Title, req.Description, string(images), req.Tag, id)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if r.Method == http.MethodPut {
			affected, _ := result.RowsAffected()
			if affected == 0 {
				http.Error(w, "Moment not found", http.StatusNotFound)
				return
			}
		} else {
			id64, _ := result.LastInsertId()
			id = int(id64)
		}
		moment, err := getMoment(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusCreated, moment)
	case http.MethodDelete:
		result, err := db.Exec("DELETE FROM moments WHERE id = ?", id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		affected, _ := result.RowsAffected()
		if affected == 0 {
			http.Error(w, "Moment not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

type momentScanner interface{ Scan(...any) error }

func scanMoment(scanner momentScanner) (Moment, error) {
	var m Moment
	var imageJSON string
	var userID sql.NullInt64
	if err := scanner.Scan(&m.ID, &m.Title, &m.Description, &imageJSON, &m.Tag, &userID, &m.CreatedAt, &m.UpdatedAt); err != nil {
		return m, err
	}
	if userID.Valid {
		id := int(userID.Int64)
		m.UserID = &id
	}
	if err := json.Unmarshal([]byte(imageJSON), &m.ImageURLs); err != nil {
		m.ImageURLs = []string{}
	}
	return m, nil
}

func getMoment(id int) (Moment, error) {
	row := db.QueryRow(`SELECT id, title, description, image_urls, tag, user_id, created_at, updated_at FROM moments WHERE id=?`, id)
	return scanMoment(row)
}

func handleFileUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := os.MkdirAll("/storage", 0755); err != nil {
		http.Error(w, "Unable to create storage directory", http.StatusInternalServerError)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 25<<20)
	if err := r.ParseMultipartForm(25 << 20); err != nil {
		http.Error(w, "File is required and must be smaller than 25 MB", http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file form field is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	filename := filepath.Base(header.Filename)
	ext := filepath.Ext(filename)
	if ext == "" {
		ext = ".bin"
	}
	filename = fmt.Sprintf("%d%s", time.Now().UnixNano(), strings.ToLower(ext))
	destination := filepath.Join("/storage", filename)
	output, err := os.Create(destination)
	if err != nil {
		http.Error(w, "Unable to save file", http.StatusInternalServerError)
		return
	}
	defer output.Close()
	if _, err := io.Copy(output, file); err != nil {
		http.Error(w, "Unable to save file", http.StatusInternalServerError)
		return
	}
	contentType := mime.TypeByExtension(ext)
	writeJSON(w, http.StatusCreated, map[string]string{
		"filename":    filename,
		"url":         "/files/" + filename,
		"contentType": contentType,
	})
}

func handleFileDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	filename := filepath.Base(strings.TrimPrefix(r.URL.Path, "/files/"))
	if filename == "." || filename == "" {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	http.ServeFile(w, r, filepath.Join("/storage", filename))
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
