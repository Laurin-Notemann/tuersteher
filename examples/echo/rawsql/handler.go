package rawsql

import (
	"database/sql"
	"net/http"
	"time"

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
	user, err := InsertUser(
		dbCon,
		&PGUser{
			Username:       username,
			Email:          email,
			HashedPassword: hashedPassword,
			Salt:           salt,
		})
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

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
			UserId:       user.Id,
			ExpiryDate:   cookie.Expires,
			LastSeenTime: time.Now(),
		},
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	tuersteher.AddCookieToResponse(c.Response(), cookie)

	return c.Redirect(303, "/")
}

func LoginUser(c echo.Context) error {
	dbCon := c.Get("_db").(*sql.DB)

	email := c.FormValue("email")
	password := c.FormValue("password")

	// Call to DB to get the user by email, to get later save the session with the user.Id
	user, err := SelectOneUserByEmail(dbCon, email)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, err.Error())
	}

	// Compare the password the user has input to the one the one in the db, if they are
	// not the same then it erors
	err = tuersteher.ComparePassword(password, user.Salt, user.HashedPassword)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, err.Error())
	}

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
			UserId:       user.Id,
			ExpiryDate:   cookie.Expires,
			LastSeenTime: time.Now(),
		},
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// Add the cookie data to the Response
	tuersteher.AddCookieToResponse(c.Response(), cookie)

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
