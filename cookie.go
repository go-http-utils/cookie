package cookie

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"hash"
	"net/http"
	"time"
)

// Options is used to setting cookie.
type Options struct {
	MaxAge   int    // optional, default to "/"
	Path     string // optional
	Domain   string // optional
	Secure   bool   // optional
	HTTPOnly bool   // optional, default to `true``
	Signed   bool   // optional
}

var defaultOptions = &Options{
	Path:     "/",
	HTTPOnly: true,
}

// New returns a Cookies instance with optional keygrip for signed cookies.
func New(w http.ResponseWriter, r *http.Request, keygrip ...*Keygrip) (cookie *Cookies) {
	c := &Cookies{
		req: r,
		w:   w,
	}
	if len(keygrip) > 0 {
		c.keygrip = keygrip[0]
	}
	return c
}

// Cookies manipulates http.Cookie easy, supports signed cookies.
type Cookies struct {
	req     *http.Request
	w       http.ResponseWriter
	keygrip *Keygrip
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
		if c.keygrip == nil {
			panic("required keygrip for signed cookies")
		}
		if sig, _ := c.req.Cookie(name + ".sig"); sig != nil && len(value) > 0 {
			if c.keygrip.Verify(name+"="+value, sig.Value) {
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
		cookie.Expires = time.Now().Add(d)
	} else if opts.MaxAge < 0 {
		cookie.Expires = time.Unix(1, 0)
	}
	http.SetCookie(c.w, cookie)
	if opts.Signed {
		if c.keygrip == nil {
			panic("required keygrip for signed cookie")
		}
		sig := *cookie
		sig.Value = c.keygrip.Sign(sig.Name + "=" + sig.Value)
		sig.Name = sig.Name + ".sig"
		http.SetCookie(c.w, &sig)
	}
	return c
}

// Keygrip uses for signing and verifying data through a rotating credential system.
type Keygrip struct {
	hash []hash.Hash
}

// NewKeygrip returns a Keygrip instance with optional keys.
func NewKeygrip(keys []string) *Keygrip {
	if len(keys) == 0 {
		panic("required keys for Keygrip")
	}

	k := &Keygrip{
		hash: make([]hash.Hash, 0, len(keys)),
	}
	for _, key := range keys {
		k.hash = append(k.hash, hmac.New(sha1.New, []byte(key)))
	}
	return k
}

// Sign creates a summary with data and sha1 algorithm
// compatibility for https://github.com/pillarjs/cookies
func (k *Keygrip) Sign(data string) (sum string) {
	return base64.RawURLEncoding.EncodeToString(digest(k.hash[0], data))
}

// Verify verify the data with the given hash summary
func (k *Keygrip) Verify(data, sum string) bool {
	if current, err := base64.RawURLEncoding.DecodeString(sum); err == nil {
		for _, h := range k.hash {
			if subtle.ConstantTimeCompare(digest(h, data), current) == 1 {
				return true
			}
		}
	}
	return false
}

func digest(h hash.Hash, data string) (buf []byte) {
	h.Write([]byte(data))
	buf = h.Sum(nil)
	h.Reset()
	return
}
