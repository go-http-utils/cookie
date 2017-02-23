package main

import (
	"net/http"

	"github.com/go-http-utils/cookie"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cookies := cookie.New(w, r, "some key")

		cookies.Set("test", "some cookie", &cookie.Options{
			Signed:   true,
			HTTPOnly: true,
		})

		value, err := cookies.Get("test", true)
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
		} else {
			w.Write([]byte(value))
		}
	})

	http.ListenAndServe(":8080", nil)
}
