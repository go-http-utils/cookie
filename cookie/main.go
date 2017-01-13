package main

import (
	"net/http"
	"net/http/httptest"

	"github.com/go-http-utils/cookie"
)

func main() {
	req, _ := http.NewRequest("GET", "/health-check", nil)

	keys := "zxcvbnm"
	cookiekey := "test"
	cookievalue := "xxxxx"
	recorder := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie := cookie.New(w, r, &cookie.Options{
			Key:      keys,
			Signed:   true,
			HTTPOnly: true,
		})
		cookie.Set(cookiekey, cookievalue, nil)
	})

	handler.ServeHTTP(recorder, req)
}
