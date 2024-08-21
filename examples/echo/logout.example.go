package echo

import (
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/laurin-notemann/tuersteher"
)

func logoutUser(c echo.Context) error {
	// get the SessionCookie object from the request
	session, err := tuersteher.GetSessionFromCookie(c.Request())
	if err != nil {
		return err
	}

	// Delete it from the DB
	err = deleteSessionById(session.Id)
	if err != nil {
		return err
	}

	// Remove the cookie in the Response (set empty value and MaxAge -1
	// -> automatically removes cookie)
	session.RemoveCookie(c.Response())

	return c.NoContent(200)
}

var sessions = []DbSession{
	{
		Id:           "dongs",
		UserId:       uuid.New(),
		ExpiryDate:   time.Now().Add(time.Hour * 24 * 30),
		LastSeenTime: time.Now(),
		LogInTime:    time.Now(),
		IpAddress:    nil,
		Device:       nil,
	},
}

func findSessionById(sessionId string) (DbSession, error) {
	idx := slices.IndexFunc(sessions, func(s DbSession) bool { return s.Id == sessionId })
	if idx == -1 {
		return DbSession{}, errors.New("User not in list")
	}
	return sessions[idx], nil
}

func deleteSessionById(sessionId string) error {
	return nil
}
