package rawsql

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/laurin-notemann/tuersteher"
)

func RegisterUser(c echo.Context) error {
	dbCon := c.Get("_db").(*sql.DB)

	username := c.FormValue("username")
	email := c.FormValue("email")
	password := c.FormValue("password")
	confirmPassword := c.FormValue("confirm-password")

	// Built-in Function to validate the password from the users input
	if err := tuersteher.ValidatePassword(password, confirmPassword); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Generate a random string that is then used to hash the password (this needs
	// to be saved in the database
	salt, err := tuersteher.GenerateRandomString(32)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// Hash the password with the generated salt and the password
	hashedPassword := tuersteher.HashPassword(password, salt)

	// Save the username, email, the hashed password and the salt in the db

	user, err := CreateUserWithCreds(dbCon, username, email, salt, hashedPassword)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	err = createSession(c, user.Id, dbCon)

	return c.Redirect(303, "/")
}

func LoginUser(c echo.Context) error {
	dbCon := c.Get("_db").(*sql.DB)

	email := c.FormValue("email")
	password := c.FormValue("password")

	// Call to DB to get the user by email, to get later save the session with the user.Id
	user, userCreds, err := FindUserAndCredsByEmail(dbCon, email)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, err.Error())
	}

	// Compare the password the user has input to the one the one in the db, if they are
	// not the same then it erors
	err = tuersteher.ComparePassword(password, userCreds.Salt, userCreds.PasswordHash)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, err.Error())
	}

	err = createSession(c, user.Id, dbCon)

	return c.Redirect(303, "/")
}

func LogoutUser(c echo.Context) error {
	dbCon := c.Get("_db").(*sql.DB)

	// get the SessionCookie object from the request
	cookie, err := tuersteher.GetCookieFromRequest(c.Request())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// Delete session based on cookie.Value (which is also the the session id)
	err = DeleteSession(dbCon, &PGSession{Id: cookie.Value})
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// Remove the cookie in the Response (set empty value and MaxAge -1
	// which automatically removes cookie)
	tuersteher.RemoveCookie(c.Response())

	return c.Redirect(303, "/")
}

func ValidateRequest(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		dbCon := c.Get("_db").(*sql.DB)
		cookie, err := tuersteher.GetCookieFromRequest(c.Request())
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		// Get session from DB
		session, err := SelectOneSessionById(dbCon, cookie.Value)
		if err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
		}

		// Checks if the session is expired
		if time.Now().After(session.ExpiryDate) {
			return echo.NewHTTPError(http.StatusUnauthorized, "Session Expired")
		}

		// Checks if half of the expiryTime days have already passed, and if so it renews the session
		if time.Now().After(session.LogInTime.Add(session.ExpiryDate.Sub(session.LogInTime) / 2)) {
			// Set the MaxAge of the Cookie back to 30 days
			tuersteher.SetMaxAge(cookie, tuersteher.ThirtyDays)

			// Update the current session to the new ExpiryDate
			err = UpdateSession(
				dbCon,
				&PGSession{
					Id:           cookie.Value,
					ExpiryDate:   cookie.Expires,
					LastSeenTime: time.Now(),
				},
			)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
			}

			// Add the cookie with the new MaxAge to the response to set in the browser
			tuersteher.AddCookieToResponse(c.Response(), cookie)
		} else {
			// if the session is still valid we want to update the LastSeenTime nevertheless
			err = UpdateSession(
				dbCon,
				&PGSession{
					Id:           cookie.Value,
					LastSeenTime: time.Now(),
				},
			)
		}

		return next(c)
	}
}

// This redirects to the google service to be able to log in with google
func GoogleRedirect(c echo.Context) error {
	tuersteher := c.Get("_tuersteher").(*tuersteher.TuersteherOauth)
	return c.Redirect(http.StatusTemporaryRedirect, tuersteher.GetAuthUrl())
}

// After the sign in/up in google, this is the endpoint google will redirect the user to
// which will then take the information from google to either create a new account or if one already exists
// will directly log in and create a session
func GoogleCallback(c echo.Context) error {
	tuersteherGoogle, ok := c.Get("_tuersteher").(*tuersteher.TuersteherOauth)
	if !ok {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get TuersteherOauth from context")
	}
	dbCon, ok := c.Get("_db").(*sql.DB)
	if !ok {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get database connection from context")
	}

  // This is the main interaction with google which will get the user information
	tuersteherUser, err := tuersteherGoogle.GetUserInfo(c.Request())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// Call to DB to get the user by email, to get later save the session with the user.Id
	user, err := SelectOneUserByEmail(dbCon, tuersteherUser.Email)
	// This means the user is not in the database which means we need to create a new user
	if errors.Is(err, sql.ErrNoRows) {
    log.Print("rtest")

		user, err = CreateUserWithGoogleOAuth(dbCon, tuersteherUser.Name, tuersteherUser.Email, tuersteherUser.ProviderId)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
	} else if err != nil {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, err.Error())
	}

	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	err = createSession(c, user.Id, dbCon)

	return c.Redirect(http.StatusFound, "/")
}

func createSession(c echo.Context, userId uuid.UUID, dbCon *sql.DB) error {
	// Generate a cookie, that has the name="tuersteher_session" and a random generated
	// string as a value, MaxAge is set to 30days
	cookie, err := tuersteher.NewCookie()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// To change a value of the cookie just set the value like so:
	cookie.SameSite = http.SameSiteLaxMode
	cookie.Secure = false

	// Create Session in DB and save the cookie.Value, user.Id, and cookie.Expires
	err = InsertSession(
		dbCon,
		&PGSession{
			Id:           cookie.Value,
			UserId:       userId,
			ExpiryDate:   cookie.Expires,
			LastSeenTime: time.Now(),
		},
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// Add the cookie data to the Response
	tuersteher.AddCookieToResponse(c.Response(), cookie)

	return nil
}
