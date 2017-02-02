package cookie

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

var DefaultClient = &http.Client{}

func TestCookie(t *testing.T) {
	keys := []string{"some key"}
	keygrip := NewKeygrip(keys)

	assert.Panics(t, func() {
		NewKeygrip([]string{})
	})

	t.Run("Cookie use default options that should be", func(t *testing.T) {
		assert := assert.New(t)
		req, _ := http.NewRequest("GET", "/health-check", nil)
		cookiekey := "test"
		cookievalue := "xxxxx"
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookies := New(w, r)
			cookies.Set(cookiekey, cookievalue).Set(cookiekey, cookievalue)
		})
		handler.ServeHTTP(recorder, req)

		cookies, err := getCookie(cookiekey, recorder)
		assert.Nil(err)
		assert.Equal(cookievalue, cookies.Value)
		assert.Equal("", cookies.Domain)
		assert.Equal(true, cookies.HttpOnly)
		assert.Equal(false, cookies.Secure)
		assert.Equal(0, cookies.MaxAge)
		assert.NotNil(cookies.Expires)
		assert.Equal("/", cookies.Path)
	})

	t.Run("Cookie with sign key that should be", func(t *testing.T) {
		assert := assert.New(t)
		req, _ := http.NewRequest("GET", "/health-check", nil)
		cookiekey := "test"
		cookievalue := "xxxxx"
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookies := New(w, r, keygrip)
			cookies.Set(cookiekey, cookievalue, &Options{
				Signed:   true,
				HTTPOnly: true,
				Secure:   true,
				Domain:   "teambition.com",
				MaxAge:   3600,
				Path:     "/"})
		})
		handler.ServeHTTP(recorder, req)

		cookies, err := getCookie(cookiekey, recorder)
		assert.Nil(err)
		assert.Equal(cookievalue, cookies.Value)
		assert.Equal(true, cookies.HttpOnly)
		assert.Equal(true, cookies.Secure)
		assert.Equal("teambition.com", cookies.Domain)
		assert.Equal(3600, cookies.MaxAge)
		assert.Equal("/", cookies.Path)

		cookies, err = getCookie(cookiekey+".sig", recorder)
		assert.Nil(err)
		assert.NotNil(cookies)
		assert.Equal(cookies.Value, keygrip.Sign(cookiekey+"="+cookievalue))
	})

	t.Run("Cookie with custom Options that should be", func(t *testing.T) {
		assert := assert.New(t)
		req, _ := http.NewRequest("GET", "/health-check", nil)
		cookiekey := "test"
		cookievalue := "xxxxx"
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookies := New(w, r, keygrip)
			cookies.Set(cookiekey, cookievalue, &Options{
				Signed: false,
			})
		})
		handler.ServeHTTP(recorder, req)

		cookies, err := getCookie(cookiekey, recorder)
		assert.Nil(err)
		assert.Equal(cookievalue, cookies.Value)
		cookies, err = getCookie(cookiekey+".sig", recorder)
		assert.Nil(cookies)
		assert.NotNil(err)
	})

	t.Run("Cookie with get that should be", func(t *testing.T) {
		assert := assert.New(t)
		req, _ := http.NewRequest("GET", "/health-check", nil)

		cookiekey := "test"
		cookievalue := "xxxxx"
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookies := New(w, r, keygrip)
			opts := &Options{
				Signed: true,
				MaxAge: -1,
			}
			cookies.Set(cookiekey, cookievalue, opts)
		})
		handler.ServeHTTP(recorder, req)

		//====second========
		req, _ = http.NewRequest("GET", "/health-check", nil)

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
			cookies := New(w, r, keygrip)

			val, err := cookies.Get(cookiekey + "cc")
			assert.NotNil(err)

			val, err = cookies.Get(cookiekey, true)
			assert.Nil(err)
			assert.Equal(val, cookievalue)

			val, err = cookies.Get(cookiekey + ".sig")
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
		assert.Equal("modify", cookies.Value)

		cookies, err = getCookie(cookiekey+".sig", recorder)
		req.AddCookie(cookies)
		assert.NotNil(cookies)
		assert.Nil(err)

		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Log(r.Cookies())
			cookies := New(w, r, keygrip)
			val, err := cookies.Get(cookiekey, true)
			assert.Equal(err.Error(), "invalid signed cookie")
			assert.NotEqual(val, cookievalue)
			assert.Equal("", val)
		})
		handler.ServeHTTP(recorder, req)
	})

	t.Run("Cookie with wrong Options that should be", func(t *testing.T) {
		assert := assert.New(t)

		cookiekey := "test"
		req, _ := http.NewRequest("GET", "/health-check", nil)
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				rec := recover()
				assert.NotNil(rec)
			}()

			opts := &Options{
				Signed: true,
			}
			cookies := New(w, r)
			cookievalue := "xxxxx"
			cookies.Set(cookiekey+"ccc", cookievalue)
			cookies.Set(cookiekey, cookievalue, opts)
		})
		handler.ServeHTTP(recorder, req)

		cookies, err := getCookie(cookiekey+"ccc", recorder)
		req.AddCookie(cookies)
		assert.NotNil(cookies)
		assert.Nil(err)

		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				rec := recover()
				assert.NotNil(rec)
			}()

			cookies := New(w, r)
			cookies.Get(cookiekey+"ccc", true)
		})
		handler.ServeHTTP(recorder, req)
	})

	t.Run("Cookie with multi keys that should be", func(t *testing.T) {
		assert := assert.New(t)
		req, _ := http.NewRequest("GET", "/health-check", nil)
		cookiekey := "test"
		cookievalue := "xxxxx"
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookies := New(w, r, keygrip)
			opts := &Options{
				Signed: true,
				MaxAge: -1,
			}
			cookies.Set(cookiekey, cookievalue, opts)
		})

		handler.ServeHTTP(recorder, req)
		//====second========
		keys = []string{"newkey", "zxcvbnm"}
		req, _ = http.NewRequest("GET", "/health-check", nil)

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
			cookies := New(w, r, keygrip)
			val, err := cookies.Get(cookiekey, true)
			assert.Nil(err)
			assert.Equal(val, cookievalue)

			val, err = cookies.Get(cookiekey + ".sig")
			assert.Nil(err)
			assert.NotEmpty(val)
		})

		handler.ServeHTTP(recorder, req)
		//====third trying to modify cookie with mock value========
		keys = []string{"newnewkey", "newkey", "zxcvbnm"}
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
			cookies := New(w, r, keygrip)
			val, err := cookies.Get(cookiekey, true)
			assert.Equal(err.Error(), "invalid signed cookie")
			assert.NotEqual(val, cookievalue)
			assert.Equal("", val)
		})
		handler.ServeHTTP(recorder, req)
	})
}

func TestPillarjsCookie(t *testing.T) {
	keygrip := NewKeygrip([]string{"some key"})

	t.Run("should parse pillarjs/cookies signed cookie", func(t *testing.T) {
		assert := assert.New(t)

		req, _ := http.NewRequest("GET", "/", nil)
		// this cookie is generated by https://github.com/pillarjs/cookies/tree/0.6.2
		req.Header.Set("Cookie", "cookieKey=cookie value; cookieKey.sig=JROAKAAIUzC3_akvMb7PKF4l5h4")
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookies := New(w, r, keygrip)
			val, err := cookies.Get("cookieKey")
			assert.Nil(err)
			assert.Equal("cookie value", val)

			val, err = cookies.Get("cookieKey", true)
			assert.Nil(err)
			assert.Equal("cookie value", val)
		})
		handler.ServeHTTP(recorder, req)
	})

	t.Run("should error when parse pillarjs/cookies tampered cookie", func(t *testing.T) {
		assert := assert.New(t)

		req, _ := http.NewRequest("GET", "/", nil)
		// tampered the cookie
		req.Header.Set("Cookie", "cookieKey=cookie value1; cookieKey.sig=JROAKAAIUzC3_akvMb7PKF4l5h4")
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookies := New(w, r, keygrip)
			val, err := cookies.Get("cookieKey")
			assert.Nil(err)
			assert.Equal("cookie value1", val)

			val, err = cookies.Get("cookieKey", true)
			assert.Equal("", val)
			assert.Equal("invalid signed cookie", err.Error())
		})
		handler.ServeHTTP(recorder, req)
	})
}

func getCookie(name string, recorder *httptest.ResponseRecorder) (*http.Cookie, error) {
	res := &http.Response{Header: http.Header{"Set-Cookie": recorder.HeaderMap["Set-Cookie"]}}
	for _, val := range res.Cookies() {
		if val.Name == name {
			return val, nil
		}
	}
	return nil, errors.New("not exists")
}
