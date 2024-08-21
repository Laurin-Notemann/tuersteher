package echo

import (
	"errors"
	"net/http"
	"slices"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/laurin-notemann/tuersteher"
)

func loginUser(c echo.Context) error {
	email := "test@gmail.com"  // c.FormValue("emai")
	password := "TestPassword" // c.FormValue("password")

  // Look for the user in the DB
	user, err := findUserByEmail(email)
	if err != nil {
		return err
	}

  // Compare the password the user has input to the one the one in the db 
	err = tuersteher.ComparePassword(password, user.Salt, user.HashedPassword)
	if err != nil {
		return err
	}

	// Generate a sessionCookie, which will get a random generated ID and has
	// default cookie values, default MaxAge is 30days
	sessionCookie, err := tuersteher.NewSession()
	if err != nil {
		return err
	}

	// To change a value of a cookie just set the value like so:
	sessionCookie.Options.SameSite = http.SameSiteLaxMode
	sessionCookie.Options.Secure = false

	// Create Session in DB and save the session.Id
	_, err = createSession(sessionCookie.Id, user.Id, nil, nil, sessionCookie.Options.MaxAge)
	if err != nil {
		return err
	}

	// Add the cookie data to the Response
	sessionCookie.AddSessionToResponse(c.Response())

	return c.NoContent(200)
}

var users = []User{
	{
    Id: uuid.New(),
		Username:       "test",
		Email:          "test@gmail.com",
		HashedPassword: "test",
		Salt:           "test",
	},
}

func findUserByEmail(email string) (User, error) {
	idx := slices.IndexFunc(users, func(u User) bool { return u.Email == email })
	if idx == -1 {
		return User{}, errors.New("User not in list")
	}
	return users[idx], nil
}
