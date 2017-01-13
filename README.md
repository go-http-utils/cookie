# cookie
Advanced cookie library, support secure cookies.

[![Build Status](https://travis-ci.org/go-http-utils/cookie.svg?branch=master)](https://travis-ci.org/go-http-utils/cookie)
[![Coverage Status](http://img.shields.io/coveralls/go-http-utils/cookie.svg?style=flat-square)](https://coveralls.io/r/go-http-utils/cookie)
[![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/go-http-utils/cookie/master/LICENSE)
[![GoDoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](http://godoc.org/github.com/go-http-utils/cookie)



##API
###cookie = cookie.New(w, r, &cookie.Options{})
The function create&&return an operational instance for add or get cookie by cookie.Options.

###cookie.Options struct
* `MaxAge`: a number representing the milliseconds for expiry (`0` by default)
* `Expires`: Indicating the cookie's expiration date 
* `Path`: a string indicating the path of the cookie (`/` by default).
* `Domain`: a string indicating the domain of the cookie (no default).
* `Secure`: a boolean indicating whether the cookie is only to be sent over HTTP(S).
* `HTTPOnly`: a boolean indicating whether the cookie is only to be sent over HTTP(S).
* `signed`: a boolean indicating whether the cookie is to be signed (`false` by default). If this is true, another cookie of the same name with the `.sig` suffix appended will also be sent.

###cookie.Set(name string, val string, options *Options)

###cookie.Get(name string, options *Options)

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
