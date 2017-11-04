package cookie

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"time"
)

// Options is used to setting cookie.
type Options struct {
	MaxAge   int    // optional
	Path     string // optional, default to "/"
	Domain   string // optional
	Secure   bool   // optional
	HTTPOnly bool   // optional, default to `true``
	Signed   bool   // optional
}

var defaultOptions = &Options{
	Path:     "/",
	HTTPOnly: true,
}

// default hash function
var hasher = func(key, data string) []byte {
	h := hmac.New(sha1.New, []byte(key))
	h.Write([]byte(data))
	return h.Sum(nil)
}

// SetHash set a global hash function for signed cookies, default to:
//
//  func(key, data string) []byte {
//  	h := hmac.New(sha1.New, []byte(key))
//  	h.Write([]byte(data))
//  	return h.Sum(nil)
//  }
//
// The default hash is for compatibility with https://github.com/pillarjs/cookies
// But it is easy to crack secret key. You should set a custom hash function, such as:
//
//  func(key, data string) []byte {
//  	h := hmac.New(sha256.New, []byte(key))
//  	h.Write([]byte(data))
//  	h.Write(salt) // some salt bytes
//  	return h.Sum(nil)
//  }
//
func SetHash(fn func(key, data string) []byte) {
	if fn == nil {
		panic("invalid hash function")
	}
	hasher = fn
}

// New returns a Cookies instance with optional keys for signed cookies.
func New(w http.ResponseWriter, r *http.Request, keys ...string) (cookie *Cookies) {
	c := &Cookies{
		req: r,
		w:   w,
	}
	if len(keys) > 0 {
		c.keys = keys
	}
	return c
}

// Cookies manipulates http.Cookie easy, supports signed cookies.
type Cookies struct {
	req  *http.Request
	w    http.ResponseWriter
	keys []string
}

// Get returns the cookie with the given name from the Cookie header in the request.
// If such a cookie exists, its value is returned. Otherwise, nothing is returned.
// signed = true can optionally be passed as the second parameter.
// In this case, a signature cookie (a cookie of same name ending with the .sig suffix appended)
// is fetched. If the signature cookie does exist, cookie will check the hash of cookie-value
// whether matches registered keys.
func (c *Cookies) Get(name string, signed ...bool) (value string, err error) {
	cookie, err := c.req.Cookie(name)
	if cookie == nil {
		return
	}
	value = cookie.Value
	if len(signed) > 0 && signed[0] {
		if c.keys == nil {
			panic("required keys for signed cookies")
		}
		if sig, _ := c.req.Cookie(name + ".sig"); sig != nil && len(value) > 0 {
			if verify(c.keys, name+"="+value, sig.Value) {
				return
			}
		}
		value = ""
		err = errors.New("invalid signed cookie")
	}
	return
}

// Set set the given cookie to the response and returns the current context to allow chaining.
// If options omit, it will use default options.
func (c *Cookies) Set(name, val string, options ...*Options) *Cookies {
	opts := defaultOptions
	if len(options) > 0 {
		opts = options[0]
	}

	cookie := &http.Cookie{
		Name:     name,
		Value:    val,
		HttpOnly: opts.HTTPOnly,
		Secure:   opts.Secure,
		MaxAge:   opts.MaxAge,
		Domain:   opts.Domain,
		Path:     opts.Path,
	}
	if opts.MaxAge > 0 {
		d := time.Duration(opts.MaxAge) * time.Second
		cookie.Expires = time.Now().Add(d).UTC()
	} else if opts.MaxAge < 0 {
		cookie.Expires = time.Unix(1, 0).UTC()
	}
	http.SetCookie(c.w, cookie)
	if opts.Signed {
		if c.keys == nil {
			panic("required keys for signed cookie")
		}
		sig := *cookie
		if sig.Value != "" {
			sig.Value = sign(c.keys[0], sig.Name+"="+sig.Value)
		}
		sig.Name = sig.Name + ".sig"
		http.SetCookie(c.w, &sig)
	}
	return c
}

// Remove remove the given cookie
func (c *Cookies) Remove(name string, options ...*Options) {
	opts := *defaultOptions // should copy because we will change MaxAge
	if len(options) > 0 {
		opts = *options[0]
	}
	opts.MaxAge = -1
	c.Set(name, "", &opts)
}

// sign creates a summary with data and sha1 algorithm
func sign(key, data string) string {
	return base64.RawURLEncoding.EncodeToString(hasher(key, data))
}

// Verify verify the data with the given hash summary
func verify(keys []string, data, checkSum string) bool {
	if current, err := base64.RawURLEncoding.DecodeString(checkSum); err == nil {
		for _, key := range keys {
			if subtle.ConstantTimeCompare(hasher(key, data), current) == 1 {
				return true
			}
		}
	}
	return false
}
