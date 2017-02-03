package cookie

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

var DefaultClient = &http.Client{}

func TestCookie(t *testing.T) {
	keys := []string{"some key"}

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

		c, err := getCookie(cookiekey, recorder)
		assert.Nil(err)
		assert.Equal(cookievalue, c.Value)
		assert.Equal("", c.Domain)
		assert.Equal(true, c.HttpOnly)
		assert.Equal(false, c.Secure)
		assert.Equal(0, c.MaxAge)
		assert.NotNil(c.Expires)
		assert.Equal("/", c.Path)
	})

	t.Run("Cookie with sign key that should be", func(t *testing.T) {
		assert := assert.New(t)

		req, _ := http.NewRequest("GET", "/health-check", nil)
		cookiekey := "test"
		cookievalue := "xxxxx"
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookies := New(w, r, []string{})
			assert.Nil(cookies.keys)

			cookies = New(w, r, keys)
			cookies.Set(cookiekey, cookievalue, &Options{
				Signed:   true,
				HTTPOnly: true,
				Secure:   true,
				Domain:   "teambition.com",
				MaxAge:   3600,
				Path:     "/"})
		})
		handler.ServeHTTP(recorder, req)

		c, err := getCookie(cookiekey, recorder)
		assert.Nil(err)
		assert.Equal(cookievalue, c.Value)
		assert.Equal(true, c.HttpOnly)
		assert.Equal(true, c.Secure)
		assert.Equal("teambition.com", c.Domain)
		assert.Equal(3600, c.MaxAge)
		assert.Equal("/", c.Path)

		c, err = getCookie(cookiekey+".sig", recorder)
		assert.Nil(err)
		assert.NotNil(c)
		assert.Equal(c.Value, sign(keys[0], cookiekey+"="+cookievalue))
	})

	t.Run("Cookie with custom Options that should be", func(t *testing.T) {
		assert := assert.New(t)

		req, _ := http.NewRequest("GET", "/health-check", nil)
		cookiekey := "test"
		cookievalue := "xxxxx"
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookies := New(w, r, keys)
			cookies.Set(cookiekey, cookievalue, &Options{
				Signed: false,
			})
		})
		handler.ServeHTTP(recorder, req)

		c, err := getCookie(cookiekey, recorder)
		assert.Nil(err)
		assert.Equal(cookievalue, c.Value)
		c, err = getCookie(cookiekey+".sig", recorder)
		assert.Nil(c)
		assert.NotNil(err)
	})

	t.Run("Cookie with get that should be", func(t *testing.T) {
		assert := assert.New(t)

		req, _ := http.NewRequest("GET", "/health-check", nil)
		cookiekey := "test"
		cookievalue := "xxxxx"
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookies := New(w, r, keys)
			opts := &Options{
				Signed: true,
				MaxAge: -1,
			}
			cookies.Set(cookiekey, cookievalue, opts)
		})
		handler.ServeHTTP(recorder, req)

		//====second========
		req, _ = http.NewRequest("GET", "/health-check", nil)

		c, err := getCookie(cookiekey, recorder)
		req.AddCookie(c)
		assert.Nil(err)
		assert.Equal(c.Value, cookievalue)

		c, err = getCookie(cookiekey+".sig", recorder)
		req.AddCookie(c)
		assert.NotNil(c)
		assert.Nil(err)

		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Log(r.Cookies())
			cookies := New(w, r, keys)

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
		c, err = getCookie(cookiekey, recorder)
		c.Value = "modify"
		req.AddCookie(c)
		assert.Nil(err)
		assert.Equal("modify", c.Value)

		c, err = getCookie(cookiekey+".sig", recorder)
		req.AddCookie(c)
		assert.NotNil(c)
		assert.Nil(err)

		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Log(r.Cookies())
			cookies := New(w, r, keys)
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

		c, err := getCookie(cookiekey+"ccc", recorder)
		req.AddCookie(c)
		assert.NotNil(c)
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

		keys := []string{"some key 1"}
		req, _ := http.NewRequest("GET", "/health-check", nil)
		cookiekey := "test"
		cookievalue := "xxxxx"
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookies := New(w, r, keys)
			opts := &Options{
				Signed: true,
				MaxAge: -1,
			}
			cookies.Set(cookiekey, cookievalue, opts)
		})

		handler.ServeHTTP(recorder, req)
		//====second========
		keys = []string{"some key 2", "some key 1"}
		req, _ = http.NewRequest("GET", "/health-check", nil)

		c, err := getCookie(cookiekey, recorder)
		req.AddCookie(c)
		assert.Nil(err)
		assert.Equal(c.Value, cookievalue)

		c, err = getCookie(cookiekey+".sig", recorder)
		req.AddCookie(c)
		assert.NotNil(c)
		assert.Nil(err)

		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Log(r.Cookies())
			cookies := New(w, r, keys)
			val, err := cookies.Get(cookiekey, true)
			assert.Nil(err)
			assert.Equal(val, cookievalue)

			val, err = cookies.Get(cookiekey + ".sig")
			assert.Nil(err)
			assert.NotEmpty(val)
		})

		handler.ServeHTTP(recorder, req)
		//====third trying to modify cookie with mock value========
		keys = []string{"some key 3", "some key 2", "some key 1"}
		req, err = http.NewRequest("GET", "/health-check", nil)
		c, err = getCookie(cookiekey, recorder)
		c.Value = "modify"
		req.AddCookie(c)
		assert.Nil(err)
		assert.Equal(c.Value, "modify")

		c, err = getCookie(cookiekey+".sig", recorder)
		req.AddCookie(c)
		assert.NotNil(c)
		assert.Nil(err)

		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Log(r.Cookies())
			cookies := New(w, r, keys)
			val, err := cookies.Get(cookiekey, true)
			assert.Equal(err.Error(), "invalid signed cookie")
			assert.NotEqual(val, cookievalue)
			assert.Equal("", val)
		})
		handler.ServeHTTP(recorder, req)
	})
}

func TestPillarjsCookie(t *testing.T) {
	keys := []string{"some key"}

	t.Run("should parse pillarjs/cookies signed cookie", func(t *testing.T) {
		assert := assert.New(t)

		req, _ := http.NewRequest("GET", "/", nil)
		// this cookie is generated by https://github.com/pillarjs/cookies/tree/0.6.2
		req.Header.Set("Cookie", "cookieKey=cookie value; cookieKey.sig=JROAKAAIUzC3_akvMb7PKF4l5h4")
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookies := New(w, r, keys)
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
			cookies := New(w, r, keys)
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

func TestSetHash(t *testing.T) {
	assert := assert.New(t)

	sum1 := sign("key", "some value")
	assert.True(verify([]string{"key"}, "some value", sum1))

	assert.Panics(func() {
		var fn func(a, b string) []byte
		SetHash(fn)
	})

	SetHash(func(key, data string) []byte {
		h := hmac.New(sha256.New, []byte(key))
		h.Write([]byte(data))
		h.Write([]byte("some salt bytes"))
		return h.Sum(nil)
	})

	sum2 := sign("key", "some value")
	assert.True(verify([]string{"key"}, "some value", sum2))
	assert.NotEqual(sum1, sum2)
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
