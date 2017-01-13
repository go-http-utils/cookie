package cookie

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"time"
)

//Options ...
type Options struct {
	MaxAge    int
	Path      string
	Domain    string
	Expires   time.Time
	Secure    bool
	HTTPOnly  bool
	Signed    bool
	OverWrite bool
	Key       string
}

//New ...
func New(res http.ResponseWriter, req *http.Request, options *Options) (cookie *Cookies) {
	cookie = &Cookies{
		request: req,
		writer:  res,
	}
	if options != nil {
		if options.Signed && len(options.Key) == 0 {
			panic("Required key for signed cookies")
		}
		cookie.opts = options
	} else {
		cookie.opts = &Options{
			Expires:  time.Now().Add(24 * time.Hour),
			Secure:   true,
			HTTPOnly: true,
			Path:     "/",
		}
	}
	return
}

//Cookies ...
type Cookies struct {
	request *http.Request
	writer  http.ResponseWriter
	opts    *Options
}

//Get ...
func (c *Cookies) Get(name string, opts *Options) (value string, err error) {
	if opts != nil {
		if opts.Signed && len(opts.Key) == 0 {
			panic("Required key for signed cookies")
		}
	}
	val, err := c.request.Cookie(name)
	if val == nil {
		return
	}
	value = val.Value
	signed := c.opts.Signed
	signkey := c.opts.Key
	if opts != nil {
		signed = opts.Signed
		signkey = opts.Key
	}
	if signed {
		var sigName = name + ".sig"
		newsignval := Sign(signkey, val.Value)
		oldsignval, _ := c.request.Cookie(sigName)
		if oldsignval == nil || newsignval != oldsignval.Value {
			value = ""
			err = errors.New("The cookie's value have different sign")
			c.Set(sigName, "", &Options{})
		}
	}
	return
}

//Set ...
func (c *Cookies) Set(name string, val string, options *Options) {
	if options != nil {
		if options.Signed && len(options.Key) == 0 {
			panic("Required key for signed cookies")
		}
	}
	var secure, httponly, Signed = c.opts.Secure, c.opts.HTTPOnly, c.opts.Signed
	var maxAge = c.opts.MaxAge
	var expires = c.opts.Expires
	var domain, path, key = c.opts.Domain, c.opts.Path, c.opts.Key

	if options != nil {
		secure, httponly, Signed = options.Secure, options.HTTPOnly, options.Signed
		maxAge = options.MaxAge
		expires = options.Expires
		domain, path, key = options.Domain, options.Path, options.Key
	}
	cookie := &http.Cookie{
		Name:     name,
		Value:    val,
		HttpOnly: httponly,
		Secure:   secure,
		MaxAge:   maxAge,
		Expires:  expires,
		Domain:   domain,
		Path:     path,
	}
	http.SetCookie(c.writer, cookie)
	if Signed {
		signcookie := *cookie
		signcookie.Value = Sign(key, val)
		signcookie.Name = signcookie.Name + ".sig"
		http.SetCookie(c.writer, &signcookie)
	}
}

//Sign ...
func Sign(key string, data string) (sign string) {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(data))
	sign = hex.EncodeToString(mac.Sum(nil))
	return
}
