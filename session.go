package tuersteher

import (
	"errors"
	"net/http"
	"time"
)

// Options stores configuration for a session or session store.
type CookieOptions struct {
	Path    string
	Domain  string
	Expires time.Time
	// MaxAge=0 means no Max-Age attribute specified and the cookie will be
	// deleted after the browser session ends.
	// MaxAge<0 means delete cookie immediately.
	// MaxAge>0 means Max-Age attribute present and given in seconds.
	MaxAge   int
	Secure   bool
	HttpOnly bool
	// Defaults to http.SameSiteDefaultMode
	// e.g. SameSite: http.SameSiteNoneMode
	SameSite http.SameSite
}

// This sets the Session.Options to:
// Path  : "/" ,
// Domain: "localhost",
// MaxAge: 60 * 60 * 24 * 30,
// Secure: true,
// HttpOnly: true,
// SameSite: http.SameSiteDefaultMode,
// to change one of these just do:
// session.Options.Domain = "example.com"
func NewCookie() (*http.Cookie, error) {
	id, err := GenerateRandomString(32)
	if err != nil {
		return &http.Cookie{}, err
	}

	return getCookie("tuersteher_session", id, defaultCookieSettings()), nil
}

func defaultCookieSettings() *CookieOptions {
	// MaxAge is an integer per second
	maxAge := 60 * 60 * 24 * 30
	return &CookieOptions{
		Path:     "/",
		Domain:   "localhost",
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteDefaultMode,
	}
}

func SetMaxAge(c *http.Cookie, maxAge int) {
	c.MaxAge = maxAge
	if maxAge > 0 {
		duration := time.Duration(maxAge) * time.Second
		c.Expires = time.Now().Add(duration)
	} else if maxAge < 0 {
		c.Expires = time.Unix(1, 0)
	}
}

// AddCookieToResponse:
// Takes a http.ResponseWriter and adds "Set-Cookie" header to the Response
// with the values of the Session object that was created previously.
// Name of the cookie is automatically set to "tuersteher_session" and value
// of the cookie is the id of the sessionCookie (same as the id that should be
// saved int the database
func AddCookieToResponse(w http.ResponseWriter, c *http.Cookie) {
	http.SetCookie(w, c)
}

// Remove the cookie in the Response (set empty value and MaxAge -1
// which automatically removes cookie)
func RemoveCookie(w http.ResponseWriter) {
	options := defaultCookieSettings()
	options.MaxAge = -1
	http.SetCookie(w, getCookie("tuersteher_session", "", options))
}

func getCookie(name, value string, options *CookieOptions) *http.Cookie {
	cookie := cookieFromOptions(name, value, options)
	if options.MaxAge > 0 {
		duration := time.Duration(options.MaxAge) * time.Second
		cookie.Expires = time.Now().Add(duration)
	} else if options.MaxAge < 0 {
		cookie.Expires = time.Unix(1, 0)
	}
	return cookie
}

func cookieFromOptions(name, value string, options *CookieOptions) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     options.Path,
		Domain:   options.Domain,
		MaxAge:   options.MaxAge,
		Secure:   options.Secure,
		HttpOnly: options.HttpOnly,
		SameSite: options.SameSite,
	}
}

// GetCookieFromRequest take the request as a parameter and searches for the cookie
// with the name "tuersteher_session" and then returns the value of that session
func GetCookieFromRequest(r *http.Request) (*http.Cookie, error) {
	cookie, err := find(
		r.Cookies(),
		func(cookie *http.Cookie) bool {
			return cookie.Name == "tuersteher_session"
		},
	)
	if err != nil {
		return &http.Cookie{}, err
	}

	return cookie, nil
}

func find[T any](collection []T, search func(item T) bool) (T, error) {
	for i := range collection {
		if search(collection[i]) {
			return collection[i], nil
		}
	}

	var result T
	return result, errors.New("Item not found.")
}
