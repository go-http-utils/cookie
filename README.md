Cookie
====
Advanced cookie library for Go, support signed cookies.

[![Build Status](https://travis-ci.org/go-http-utils/cookie.svg?branch=master)](https://travis-ci.org/go-http-utils/cookie)
[![Coverage Status](http://img.shields.io/coveralls/go-http-utils/cookie.svg?style=flat-square)](https://coveralls.io/r/go-http-utils/cookie)
[![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/go-http-utils/cookie/master/LICENSE)
[![GoDoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](http://godoc.org/github.com/go-http-utils/cookie)

## Features

1. **Lazy**: Since cookie verification against multiple keys could be expensive, cookies are only verified lazily when accessed, not eagerly on each request.
2. **Convenient**: Signed cookies are stored the same way as unsigned cookies. An additional signature cookie is stored for each signed cookie, using a standard naming convention (_cookie-name_`.sig`). This allows other libraries to access the original cookies without having to know the signing mechanism.
3. **compatibility** for https://github.com/pillarjs/cookies

## API

### cookie.New(w http.ResponseWriter, r *http.Request[, keys ...string])
It returns a Cookies instance with optional keygrip for signed cookies.

### cookies.Set(name, val string[, opts *Options])
It set the given cookie to the response and returns the current context to allow chaining. If options omit, it will use default options.

**Options:**
* `MaxAge`: a number representing the milliseconds for expiry (default to `0`)
* `Path`: a string indicating the path of the cookie (default to `"/"`).
* `Domain`: a string indicating the domain of the cookie (default to `""`).
* `Secure`: a boolean indicating whether the cookie is only to be sent over HTTP(S) (default to `false`).
* `HTTPOnly`: a boolean indicating whether the cookie is only to be sent over HTTP(S) (default to `true`).
* `Signed`: a boolean indicating whether the cookie is to be signed (default to `false`). If this is true, another cookie of the same name with the `.sig` suffix appended will also be sent.

### cookies.Get(name string[, signed bool])

It returns the cookie with the given name from the Cookie header in the request. If such a cookie exists, its value is returned. Otherwise, nothing is returned. signed = true can optionally be passed as the second parameter. In this case, a signature cookie (a cookie of same name ending with the .sig suffix appended) is fetched. If the signature cookie does exist, cookie will check the hash of cookie-value whether matches registered keys.

## Example

```go
package main

import (
	"net/http"

	"github.com/go-http-utils/cookie"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cookies := cookie.New(w, r, "some key")

		cookies.Set("test", "some cookie", &cookie.Options{
			Signed:   true,
			HTTPOnly: true,
		})

		value, err := cookies.Get("test", true)
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
		} else {
			w.Write([]byte(value))
		}
	})

	http.ListenAndServe(":8080", nil)
}
```
