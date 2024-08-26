package main

import (
	"database/sql"
	"io"
	"log"
	"net/http"
	"os"
	"text/template"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/laurin-notemann/tuersteher"
	"github.com/laurin-notemann/tuersteher/example/echo/rawsql"
	_ "github.com/lib/pq"
)

var dbUrl = "postgresql://postgres:admin@127.0.0.1:5432/test?sslmode=disable"

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func dbMiddleware(db *sql.DB) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set("_db", db)
			return next(c)
		}
	}
}

func oauthMiddleware(tuersteher *tuersteher.TuersteherOauth) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set("_tuersteher", tuersteher)
			return next(c)
		}
	}
}

func main() {
	// Get basic sql postgres connection to execute sql statements
	dbCon, err := sql.Open("postgres", dbUrl)
	if err != nil {
		log.Fatal(err)
	}
	err = dbCon.Ping()
	if err != nil {
		log.Fatal(err)
	}

	// Create User and Session Table if they do not exist yet (this is only one
	// example of how to create these table, they can be created in any way)
	err = rawsql.CreateUserTable(dbCon)
	if err != nil {
		log.Fatal(err)
	}
	err = rawsql.CreateUserCredentialsTable(dbCon)
	if err != nil {
		log.Fatal(err)
	}
	err = rawsql.CreateOauthProviderTable(dbCon)
	if err != nil {
		log.Fatal(err)
	}
	err = rawsql.CreateUserOauthAccountsTable(dbCon)
	if err != nil {
		log.Fatal(err)
	}
	err = rawsql.CreateSessionTable(dbCon)
	if err != nil {
		log.Fatal(err)
	}

	// Template renderer for basic HTML pages
	t := &Template{
		templates: template.Must(template.ParseGlob("views/*.html")),
	}

	tuersteher, err := tuersteher.NewGoogleTuersteherOauth(tuersteher.OauthOptions{
		ClientId:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
    RedirectUrl:  "http://localhost:3050/login/google/callback",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Basic echo setup
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(dbMiddleware(dbCon))
	e.Use(oauthMiddleware(&tuersteher))
	e.Renderer = t

	e.GET("/", indexRoute)
	e.GET("/login", loginRoute)
	e.GET("/register", registerRoute)

	// Post request for the login, regsiter and logout routes
	e.POST("/register", rawsql.RegisterUser)
	e.POST("/login", rawsql.LoginUser)
	e.POST("/logout", rawsql.LogoutUser)

	e.GET("/login/google", rawsql.GoogleRedirect)
	e.GET("/login/google/callback", rawsql.GoogleCallback)

	// test get request that is protected
	e.GET("/test-protected", func(c echo.Context) error {
		log.Print("Success")
		return c.String(200, "Moin Meister")
	}, rawsql.ValidateRequest)

	e.Logger.Fatal(e.Start("localhost:3050"))

}

// These are basic route to render the html pages
func indexRoute(c echo.Context) error {
	return c.Render(http.StatusOK, "index.html", "")
}

func loginRoute(c echo.Context) error {
	return c.Render(http.StatusOK, "login.html", "")
}

func registerRoute(c echo.Context) error {
	return c.Render(http.StatusOK, "register.html", "")
}
