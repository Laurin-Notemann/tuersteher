package echo

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/laurin-notemann/tuersteher"
)

func registerUser(c echo.Context) error {
	c.FormValue("username")
	username := "test"                // c.FormValue("username")
	email := "test@gmail.com"         // c.FormValue("emai")
	password := "TestPassword"        // c.FormValue("password")
	confirmPassword := "TestPassword" // c.FormValue("confirm-password")

  // Built-in Function to validate the password from the users input
	if err := tuersteher.ValidatePassword(password, confirmPassword); err != nil {
		return err
	}

	// Generate a random string that is then used to hash the password (this needs
  // to be saved in the database
	salt, err := tuersteher.GenerateRandomString(32)
	if err != nil {
		return err
	}

  // Hash the password with the generated salt and the password
	hashedPassword := tuersteher.HashPassword(password, salt)

  // Save the username, email, the hashed password and the salt in the db 
	user, err := createUser(username, email, hashedPassword, salt)
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

// This would also be a schema in the db
type User struct {
	Id             uuid.UUID
	Username       string
	Email          string
	HashedPassword string
	Salt           string
}

// This would have to be the user self made function provided as an example
func createUser(username, email, password, salt string) (User, error) {
	id, err := uuid.NewV6()
	if err != nil {
		return User{}, err
	}

	// This would be the call to DB
	user := User{
		Id:             id,
		Username:       username,
		Email:          email,
		HashedPassword: password,
		Salt:           salt,
	}
	return user, nil
}

type DbSession struct {
	Id           string
	UserId       uuid.UUID
	ExpiryDate   time.Time
	LastSeenTime time.Time
	LogInTime    time.Time
	IpAddress    *string // -> more location like country bcs of dynamic ip address
	Device       *string
}

func createSession(sessinId string, userId uuid.UUID, ipAddress, device *string, maxAge int) (DbSession, error) {
	session := DbSession{
		Id:     sessinId,
		UserId: userId,
		// adds 30 days
		ExpiryDate:   time.Now().Add(time.Second * time.Duration(maxAge)),
		LastSeenTime: time.Now(),
		LogInTime:    time.Now(),
		IpAddress:    ipAddress,
		Device:       device,
	}
	return session, nil

}

func updateLastSeenTime (s *DbSession) {
  s.LastSeenTime = time.Now()
}
