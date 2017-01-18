package cookie

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"time"
)

//GlobalOptions Global Options that used for to create new cookie instance.
type GlobalOptions struct {
	MaxAge   int
	Path     string
	Domain   string
	Secure   bool
	HTTPOnly bool
	Keys     []string
}

//Options  Options
type Options struct {
	MaxAge   int
	Path     string
	Domain   string
	Secure   bool
	HTTPOnly bool
	Signed   bool
}

//New The function create&&return an operational cookie instance by cookie.GlobalOptions.
func New(res http.ResponseWriter, req *http.Request, options ...*GlobalOptions) (cookie *Cookies) {
	cookie = &Cookies{
		request: req,
		writer:  res,
	}
	var opts *GlobalOptions
	if len(options) > 0 {
		opts = options[0]
	}
	if opts != nil {
		cookie.opts = opts
	} else {
		cookie.opts = &GlobalOptions{
			MaxAge:   86400 * 7,
			Secure:   true,
			HTTPOnly: true,
			Path:     "/",
		}
	}
	return
}

//Cookies Secure Cookie
type Cookies struct {
	request *http.Request
	writer  http.ResponseWriter
	opts    *GlobalOptions
}

//Get This extracts the cookie with the given name from the Cookie header in the request. If such a cookie exists, its value is returned. Otherwise, nothing is returned. { signed: true } can optionally be passed as the second parameter options. In this case, a signature cookie (a cookie of same name ending with the .sig suffix appended) is fetched. If the signature cookie does exist, cookie will check the hash of cookie-value whether matches registered key:
func (c *Cookies) Get(name string, options ...*Options) (value string, err error) {
	var signed bool
	if len(options) > 0 {
		opts := options[0]
		signed = opts.Signed
		if signed && len(c.opts.Keys) == 0 {
			panic("Required key for signed cookies")
		}
	}
	val, err := c.request.Cookie(name)
	if val == nil {
		return
	}
	value = val.Value
	if signed {
		var sigName = name + ".sig"
		oldsignval, _ := c.request.Cookie(sigName)
		for _, key := range c.opts.Keys {
			newsignval := Sign(key, val.Value)
			if oldsignval != nil && newsignval == oldsignval.Value {
				value = val.Value
				err = nil
				break
			} else {
				value = ""
				err = errors.New("The cookie's value have different sign")
			}
		}
	}
	return
}

//Set This sets the given cookie to the response and returns the current context to allow chaining.
//If the options object is nil, it will use global options or default options.
func (c *Cookies) Set(name string, val string, options ...*Options) *Cookies {
	var secure, httponly = c.opts.Secure, c.opts.HTTPOnly
	var Signed bool
	var maxAge = c.opts.MaxAge
	var domain, path, key = c.opts.Domain, c.opts.Path, ""

	if len(c.opts.Keys) > 0 {
		key = c.opts.Keys[0]
	}

	if len(options) > 0 {
		opts := options[0]
		Signed = opts.Signed
		if Signed && key == "" {
			panic("Required key for signed cookies")
		}
		secure, httponly = opts.Secure, opts.HTTPOnly
		maxAge = opts.MaxAge
		domain, path = opts.Domain, opts.Path
	}
	cookie := &http.Cookie{
		Name:     name,
		Value:    val,
		HttpOnly: httponly,
		Secure:   secure,
		MaxAge:   maxAge,
		Domain:   domain,
		Path:     path,
	}
	if maxAge > 0 {
		d := time.Duration(maxAge) * time.Second
		cookie.Expires = time.Now().Add(d)
	} else if maxAge < 0 {
		cookie.Expires = time.Unix(1, 0)
	}
	http.SetCookie(c.writer, cookie)
	if Signed {
		signcookie := *cookie
		signcookie.Value = Sign(key, val)
		signcookie.Name = signcookie.Name + ".sig"
		http.SetCookie(c.writer, &signcookie)
	}
	return c
}

//Sign Use sha256 to sign data by the key parameter
func Sign(key string, data string) (sign string) {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(data))
	sign = hex.EncodeToString(mac.Sum(nil))
	return
}
