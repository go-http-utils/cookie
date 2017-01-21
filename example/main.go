package main

import (
	"net/http"
	"net/http/httptest"

	"github.com/go-http-utils/cookie"
)

func main() {
	req, _ := http.NewRequest("GET", "/health-check", nil)

	keys := []string{"zxcvbnm"}
	cookiekey := "test"
	cookievalue := "xxxxx"
	recorder := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookies := cookie.New(w, r, &cookie.GlobalOptions{
			Keys: keys,
		})
		cookies.Set(cookiekey, cookievalue, &cookie.Options{
			Signed:   true,
			HTTPOnly: true,
		})
	})

	handler.ServeHTTP(recorder, req)
}
