package tuersteher

import (
	"errors"
	"net/http"
	"time"
)

type SessionCookie struct {
	Id      string
	Options *CookieOptions
}

// Options stores configuration for a session or session store.
type CookieOptions struct {
	Path   string
	Domain string
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
func NewSession() (SessionCookie, error) {
	id, err := GenerateRandomString(32)

	if err != nil {
		return SessionCookie{}, err
	}

	return SessionCookie{
		Id:      id,
		Options: defaultCookieSettings(),
	}, nil
}

func defaultCookieSettings() *CookieOptions {
	return &CookieOptions{
		Path:     "/",
		Domain:   "localhost",
		MaxAge:   60 * 60 * 24 * 30,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteDefaultMode,
	}
}

// AddSessionToResponse:
// Takes a http.ResponseWriter and adds "Set-Cookie" header to the Response
// with the values of the Session object that was created previously.
// Name of the cookie is automatically set to "tuersteher_session" and value
// of the cookie is the id of the sessionCookie (same as the id that should be
// saved int the database
func (s *SessionCookie) AddSessionToResponse(w http.ResponseWriter) error {
	if s.Options == nil {
		return errors.New("No options are given")
	}
	http.SetCookie(w, NewCookie("tuersteher_session", s.Id, s.Options))
	return nil
}

func (s *SessionCookie) RemoveCookie(w http.ResponseWriter) {
	s.Options.MaxAge = -1
	http.SetCookie(w, NewCookie("tuersteher_session", "", s.Options))
}

func NewCookie(name, value string, options *CookieOptions) *http.Cookie {
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

// GetIdFromCookie take the request as a parameter and searches for the cookie
// with the name "tuersteher_session" and then returns the value of that session
func GetSessionFromCookie(r *http.Request) (SessionCookie, error) {
	cookies := r.Cookies()
	cookie, err := Find(cookies, func(cookie *http.Cookie) bool { return cookie.Name == "tuersteher_session" })
	if err != nil {
		return SessionCookie{}, err
	}

	return SessionCookie{
		Id: cookie.Value,
		Options: &CookieOptions{
			Path:     cookie.Path,
			Domain:   cookie.Domain,
			MaxAge:   cookie.MaxAge,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HttpOnly,
			SameSite: cookie.SameSite,
		},
	}, nil
}

func Find[T any](collection []T, search func(item T) bool) (T, error) {
	for i := range collection {
		if search(collection[i]) {
			return collection[i], nil
		}
	}

	var result T
	return result, errors.New("Item not found.")
}
