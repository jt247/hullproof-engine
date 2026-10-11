package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func main() {
	r := chi.NewRouter()
	r.Post("/api/notes", createNote)
	r.Get("/api/export", exportUsers)
	r.Post("/api/login", login)
	r.Post("/webhooks/pay", payWebhook)

	r.Group(func(r chi.Router) {
		r.Use(requireUser)
		r.Delete("/api/notes/{id}", deleteNote)
		r.Post("/api/admin/users/role", setRole)
		r.Post("/api/import", importPage)
		r.Post("/api/upload", upload)
		r.Get("/api/items", listItems)
	})
	http.ListenAndServe(":3000", r)
}
