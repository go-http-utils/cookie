package cookie_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"time"

	"github.com/go-http-utils/cookie"
	"github.com/stretchr/testify/assert"
)

var DefaultClient = &http.Client{}

func TestCookie(t *testing.T) {

	t.Run("Cookie use default options that should be", func(t *testing.T) {
		assert := assert.New(t)
		req, err := http.NewRequest("GET", "/health-check", nil)
		if err != nil {
			t.Fatal(err)
		}
		cookiekey := "test"
		cookievalue := "xxxxx"
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie := cookie.New(w, r, nil)
			cookie.Set(cookiekey, cookievalue, nil)
		})
		handler.ServeHTTP(recorder, req)
		request := &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}}
		cookies, err := request.Cookie(cookiekey)
		assert.Nil(err)
		assert.Equal(cookies.Value, cookievalue)
		assert.Equal(cookies.Domain, "")
		assert.Equal(cookies.HttpOnly, false)
		assert.Equal(cookies.Secure, false)
		assert.Equal(cookies.MaxAge, 0)
		assert.NotNil(cookies.Expires)
		assert.Equal(cookies.Path, "")
	})
	t.Run("Cookie with sign key that should be", func(t *testing.T) {
		assert := assert.New(t)
		req, err := http.NewRequest("GET", "/health-check", nil)
		if err != nil {
			t.Fatal(err)
		}
		keys := "zxcvbnm"
		cookiekey := "test"
		cookievalue := "xxxxx"
		expires := time.Now().Add(time.Hour)
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie := cookie.New(w, r, &cookie.Options{
				Key:      keys,
				Signed:   true,
				HTTPOnly: true,
				Secure:   true,
				Domain:   "teambition.com",
				MaxAge:   3600,
				Path:     "/",
				Expires:  expires,
			})
			cookie.Set(cookiekey, cookievalue, nil)
		})

		handler.ServeHTTP(recorder, req)

		cookies, err := getCookie(cookiekey, recorder)
		assert.Nil(err)
		assert.Equal(cookies.Value, cookievalue)
		assert.Equal(cookies.HttpOnly, true)
		assert.Equal(cookies.Secure, true)
		assert.Equal(cookies.Domain, "teambition.com")
		assert.Equal(cookies.MaxAge, 3600)
		assert.Equal(cookies.Path, "/")
		assert.Equal(expires.UTC().Sub(expires), time.Duration(0))

		cookies, err = getCookie(cookiekey+".sig", recorder)

		assert.Nil(err)
		assert.NotNil(cookies)
		assert.Equal(cookies.Value, cookie.Sign(keys, cookievalue))
	})
	t.Run("Cookie with custom Options that should be", func(t *testing.T) {
		assert := assert.New(t)
		req, err := http.NewRequest("GET", "/health-check", nil)
		if err != nil {
			t.Fatal(err)
		}
		keys := "zxcvbnm"
		cookiekey := "test"
		cookievalue := "xxxxx"
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookies := cookie.New(w, r, &cookie.Options{
				Key:    keys,
				Signed: true,
			})
			cookies.Set(cookiekey, cookievalue, &cookie.Options{
				Key:    keys,
				Signed: false,
			})
		})

		handler.ServeHTTP(recorder, req)

		request := &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}}

		cookies, err := request.Cookie(cookiekey)

		assert.Nil(err)
		assert.Equal(cookies.Value, cookievalue)

		cookies, err = request.Cookie(cookiekey + ".sig")
		assert.Nil(cookies)
		assert.NotNil(err)
	})
	t.Run("Cookie with get  that should be", func(t *testing.T) {
		assert := assert.New(t)
		req, err := http.NewRequest("GET", "/health-check", nil)
        if err != nil {
			t.Fatal(err)
		}
		signkey := "zxcvbnm"
		cookiekey := "test"
		cookievalue := "xxxxx"
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookies := cookie.New(w, r, nil)
			opts := &cookie.Options{
				Key:    signkey,
				Signed: true,
			}
			cookies.Set(cookiekey, cookievalue, opts)
		})

		handler.ServeHTTP(recorder, req)
		//====second========
		req, err = http.NewRequest("GET", "/health-check", nil)

		cookies, err := getCookie(cookiekey, recorder)
		req.AddCookie(cookies)
		assert.Nil(err)
		assert.Equal(cookies.Value, cookievalue)

		cookies, err = getCookie(cookiekey+".sig", recorder)
		req.AddCookie(cookies)
		assert.NotNil(cookies)
		assert.Nil(err)

		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Log(r.Cookies())
			cookies := cookie.New(w, r, nil)
			opts := &cookie.Options{
				Key:    signkey,
				Signed: true,
			}
			val, err := cookies.Get(cookiekey, opts)
			assert.Nil(err)
			assert.Equal(val, cookievalue)

			val, err = cookies.Get(cookiekey+".sig", nil)
			assert.Nil(err)
			assert.NotEmpty(val)

		})
		handler.ServeHTTP(recorder, req)
		//====third trying to modify cookie with mock value========
		req, err = http.NewRequest("GET", "/health-check", nil)
		cookies, err = getCookie(cookiekey, recorder)
		cookies.Value = "modify"
		req.AddCookie(cookies)
		assert.Nil(err)
		assert.Equal(cookies.Value, "modify")

		cookies, err = getCookie(cookiekey+".sig", recorder)
		req.AddCookie(cookies)
		assert.NotNil(cookies)
		assert.Nil(err)

		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Log(r.Cookies())
			cookies := cookie.New(w, r, nil)
			opts := &cookie.Options{
				Key:    signkey,
				Signed: true,
			}
			val, err := cookies.Get(cookiekey, opts)
			assert.Equal(err.Error(), "The cookie's value have different sign")
			assert.NotEqual(val, cookievalue)
			assert.Equal(val, "")
		})
		handler.ServeHTTP(recorder, req)
	})
	t.Run("Cookie with wrong Options that should be", func(t *testing.T) {
		assert := assert.New(t)
		req, err := http.NewRequest("GET", "/health-check", nil)
		if err != nil {
			t.Fatal(err)
		}

		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				rec := recover()
				assert.NotNil(rec)
			}()
			opts := &cookie.Options{
				Key:    "",
				Signed: true,
			}
			cookie.New(w, r, opts)
		})
		handler.ServeHTTP(recorder, req)
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				rec := recover()
				assert.NotNil(rec)
			}()
			opts := &cookie.Options{
				Key:    "",
				Signed: true,
			}
			cookies := cookie.New(w, r, nil)
			cookiekey := "test"
			cookievalue := "xxxxx"
			cookies.Set(cookiekey, cookievalue, opts)
		})

		handler.ServeHTTP(recorder, req)
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				rec := recover()
				assert.NotNil(rec)
			}()
			opts := &cookie.Options{
				Key:    "",
				Signed: true,
			}
			cookies := cookie.New(w, r, nil)
			cookiekey := "test"
			cookies.Get(cookiekey+"ccc", nil)
			cookies.Get(cookiekey, opts)
		})
		handler.ServeHTTP(recorder, req)
	})
}

func getCookie(name string, recorder *httptest.ResponseRecorder) (*http.Cookie, error) {
	var err error
	res := &http.Response{Header: http.Header{"Set-Cookie": recorder.HeaderMap["Set-Cookie"]}}
	for _, val := range res.Cookies() {
		if val.Name == name {
			return val, nil
		}
	}
	return nil, err
}
