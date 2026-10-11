package main

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
)

func main() {
	r := chi.NewRouter()
	r.With(httprate.LimitByIP(10, time.Minute)).Post("/api/login", login)
	r.Post("/webhooks/pay", payWebhook)

	r.Group(func(r chi.Router) {
		r.Use(requireUser)
		r.Post("/api/notes", createNote)
		r.Get("/api/export", exportUsers)
		r.Delete("/api/notes/{id}", deleteNote)
		r.Post("/api/import", importPage)
		r.Post("/api/upload", upload)
		r.Get("/api/items", listItems)
	})

	r.Route("/api/admin", func(r chi.Router) {
		r.Use(requireUser, requireAdmin)
		r.Post("/users/role", setRole)
	})
	http.ListenAndServe(":3000", r)
}
