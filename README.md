# cookie
Advanced cookie library, support secure cookies.

[![Build Status](https://travis-ci.org/go-http-utils/cookie.svg?branch=master)](https://travis-ci.org/go-http-utils/cookie)
[![Coverage Status](http://img.shields.io/coveralls/go-http-utils/cookie.svg?style=flat-square)](https://coveralls.io/r/go-http-utils/cookie)
[![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/go-http-utils/cookie/master/LICENSE)
[![GoDoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](http://godoc.org/github.com/go-http-utils/cookie)


##Features
* **Lazy**: Since cookie verification against multiple keys could be expensive, cookies are only verified lazily when accessed, not eagerly on each request.
* **Secure**: All cookies are `httponly` by default, and cookies sent over SSL are `secure` by default. An error will be thrown if you try to send secure cookies over an insecure socket.
* **Convenient**: Signed cookies are stored the same way as unsigned cookies.An additional signature cookie is stored for each signed cookie, using a standard naming convention (_cookie-name_`.sig`). This allows other libraries to access the original cookies without having to know the signing mechanism.

##API
###cookie = cookie.New(w, r, &cookie.Options{})
The function create&&return an operational instance for add or get cookie by cookie.Options.

###cookie.Options struct
* `MaxAge`: a number representing the milliseconds for expiry (`0` by default)
* `Expires`: Indicating the cookie's expiration date 
* `Path`: a string indicating the path of the cookie (`/` by default).
* `Domain`: a string indicating the domain of the cookie (no default).
* `Secure`: a boolean indicating whether the cookie is only to be sent over HTTP(S) (`true` by default).
* `HTTPOnly`: a boolean indicating whether the cookie is only to be sent over HTTP(S) (`true` by default).
* `Signed`: a boolean indicating whether the cookie is to be signed (`false` by default). If this is true, another cookie of the same name with the `.sig` suffix appended will also be sent.
* `Key`：registered key for generating a signature cookie, The value was required If the 'signed' was true.

###cookie.Set(name string, val string, options *Options)
This sets the given cookie to the response and returns the current context to allow chaining.
If the options object is `nil`, it will use global options or default options.

###cookie.Get(name string, options *Options)
This extracts the cookie with the given name from the Cookie header in the request. If such a cookie exists, its value is returned. Otherwise, nothing is returned.
{ signed: true } can optionally be passed as the second parameter options. In this case, a signature cookie (a cookie of same name ending with the .sig suffix appended) is fetched.
If the signature cookie does exist, `cookie` will check the hash of cookie-value whether matches registered key:

##Example

```go
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
```
