package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	_ "github.com/go-sql-driver/mysql"
)

type User struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type Post struct {
	ID           int    `json:"id"`
	Content      string `json:"content"`
	UserID       int    `json:"user_id"`
	UserName     string `json:"user_name"`      // Optional for convenience
	ParentPostID *int   `json:"parent_post_id"` // Use pointer to allow null
	LikeCount    int    `json:"like_count"`     // Added for convenience
}

type Like struct {
	PostID int `json:"post_id"`
	UserID int `json:"user_id"`
}

var db *sql.DB

func main() {
	// Use DB_URL from the environment so Docker can connect via the "db" service name.
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		dsn = "root:password@tcp(127.0.0.1:3310)/gocrud_app"
	}

	// 1. Connect to Database
	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// 2. Define Routes
	http.HandleFunc("/users", handleUsers)       // Create (POST) & Read (GET)
	http.HandleFunc("/users/update", updateUser) // Update (PUT)
	http.HandleFunc("/users/delete", deleteUser) // Delete (DELETE)

	// Posts & Comments
	http.HandleFunc("/posts", handlePosts)
	http.HandleFunc("/posts/delete", deletePost)

	// Likes
	http.HandleFunc("/likes", handleLikes)
	http.HandleFunc("/likes/delete", unlikePost)

	fmt.Println("Server starting on :8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// 3. Handlers
func handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET": // Read All
		rows, _ := db.Query("SELECT id, name, email FROM users")
		var users []User
		for rows.Next() {
			var u User
			rows.Scan(&u.ID, &u.Name, &u.Email)
			users = append(users, u)
		}
		json.NewEncoder(w).Encode(users)

	case "POST": // Create
		var u User
		json.NewDecoder(r.Body).Decode(&u)
		_, err := db.Exec("INSERT INTO users(name, email) VALUES(?, ?)", u.Name, u.Email)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "PUT" {
		return
	}
	var u User
	json.NewDecoder(r.Body).Decode(&u)
	db.Exec("UPDATE users SET name=?, email=? WHERE id=?", u.Name, u.Email, u.ID)
	w.WriteHeader(http.StatusOK)
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		return
	}
	id := r.URL.Query().Get("id")
	db.Exec("DELETE FROM users WHERE id=?", id)
	w.WriteHeader(http.StatusNoContent)
}

func handlePosts(w http.ResponseWriter, r *http.Request) {
	// 1. Enable CORS so Flutter can talk to your API
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

	// Handle pre-flight OPTIONS request from Flutter
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	switch r.Method {
	case "GET":
		parentPostIDStr := r.URL.Query().Get("parentPostId")
		// Assume we want to know if User ID 1 liked these posts (replace with real auth later)
		currentUserID := 1

		var query string
		var rows *sql.Rows
		var err error

		// This updated SQL query uses a subquery to check if 'currentUserID' liked the post
		// Returning 1 for true, 0 for false as 'is_liked'
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

		if parentPostIDStr != "" {
			query = baseQuery + "WHERE p.parent_post_id = ? GROUP BY p.id, u.name"
			rows, err = db.Query(query, currentUserID, parentPostIDStr)
		} else {
			query = baseQuery + "WHERE p.parent_post_id IS NULL GROUP BY p.id, u.name"
			rows, err = db.Query(query, currentUserID)
		}

		if err != nil {
			log.Printf("Query error: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var posts []Post
		for rows.Next() {
			var p Post
			var isLikedInt int
			// Map the new SQL columns to your struct
			err := rows.Scan(&p.ID, &p.Content, &p.ParentPostID, &p.UserID, &p.UserName, &p.LikeCount, &isLikedInt)
			if err != nil {
				log.Printf("Scan error: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// If you add an 'IsLiked bool' to your Go struct, you'd set it here:
			// p.IsLiked = isLikedInt > 0

			posts = append(posts, p)
		}

		json.NewEncoder(w).Encode(posts)

	case "POST":
		var p Post
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "Invalid input", http.StatusBadRequest)
			return
		}

		// Basic validation
		if p.Content == "" || p.UserID == 0 {
			http.Error(w, "Content and UserID are required", http.StatusBadRequest)
			return
		}

		result, err := db.Exec("INSERT INTO posts(content, user_id, parent_post_id) VALUES(?, ?, ?)",
			p.Content, p.UserID, p.ParentPostID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Optional: Return the newly created ID
		newID, _ := result.LastInsertId()
		fmt.Printf("Created post ID: %d\n", newID)

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{"message": "Post created", "id": newID})

	case "PUT": // Update Post
		var p Post
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "Invalid input", http.StatusBadRequest)
			return
		}
		if p.ID == 0 {
			http.Error(w, "Post ID is required", http.StatusBadRequest)
			return
		}
		if p.Content == "" {
			http.Error(w, "Content is required", http.StatusBadRequest)
			return
		}

		result, err := db.Exec("UPDATE posts SET content = ? WHERE id = ?", p.Content, p.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if rowsAffected == 0 {
			http.Error(w, "Post not found", http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Post updated"})

	}
}

func deletePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		return
	}
	id := r.URL.Query().Get("id")
	db.Exec("DELETE FROM posts WHERE id=?", id)
	w.WriteHeader(http.StatusNoContent)
}

func handleLikes(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}

	var l Like
	json.NewDecoder(r.Body).Decode(&l)

	// Insert like (ignores if user already liked due to Primary Key)
	_, err := db.Exec("INSERT IGNORE INTO post_likes(post_id, user_id) VALUES(?, ?)", l.PostID, l.UserID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func unlikePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		return
	}

	postID := r.URL.Query().Get("post_id")
	userID := r.URL.Query().Get("user_id")

	db.Exec("DELETE FROM post_likes WHERE post_id=? AND user_id=?", postID, userID)
	w.WriteHeader(http.StatusNoContent)
}
