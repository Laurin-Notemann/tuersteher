package tuersteher

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"

	"golang.org/x/oauth2/google"
)

type TuersteherOauth struct {
	Cfg      *oauth2.Config
	State    string
	Userinfo string
}

type OauthOptions struct {
	ClientId     string
	ClientSecret string
	RedirectUrl  string
	Scopes       OauthScopes
}

type OauthScopes = []string

type TuersteherUser struct {
	Email      string `json:"email"`
	ProviderId string `json:"localId"`
	Name       string `json:"displayName"`
}

// Example scope:
// []string{"https://www.googleapis.com/auth/userinfo.email"}
func GetGoogleOauthConfig(options OauthOptions) *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  options.RedirectUrl,
		ClientID:     options.ClientId,
		ClientSecret: options.ClientSecret,
		Scopes:       append([]string{"openid"}, options.Scopes...),
		Endpoint:     google.Endpoint,
	}
}

func NewGoogleTuersteherOauth(options OauthOptions) (TuersteherOauth, error) {
	state, err := GenerateRandomString(32)
	if err != nil {
		return TuersteherOauth{}, err
	}

	return TuersteherOauth{
		Cfg:      GetGoogleOauthConfig(options),
		State:    state,
		Userinfo: "https://www.googleapis.com/oauth2/v2/userinfo",
	}, nil
}

func (t *TuersteherOauth) GetAuthUrl() string {
	return t.Cfg.AuthCodeURL(t.State)
}

func (t *TuersteherOauth) GetUserInfo(r *http.Request) (TuersteherUser, error) {
	var user TuersteherUser

	queryParams, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return user, fmt.Errorf("Could not parse Query Params from Request: %s", err.Error())
	}

	state := queryParams.Get("state")
	code := queryParams.Get("code")

	if state != t.State {
		return user, fmt.Errorf("Invalid OAuth state: %s", state)
	}

	token, err := t.Cfg.Exchange(r.Context(), code)
	if err != nil {
		return user, fmt.Errorf("Could not exhange code for token: %s", err.Error())
	}

	client := t.Cfg.Client(r.Context(), token)
	res, err := client.Get(t.Userinfo)
	if err != nil {
		return user, fmt.Errorf("Failed to get user info (possible issue might be that the scope is not added): %s", err.Error())
	}
	defer res.Body.Close()

	resByte, err := io.ReadAll(res.Body)
	if err != nil {
		return user, fmt.Errorf("Could not parse the body of the google api response: %s", err.Error())
	}

	err = json.Unmarshal(resByte, &user)
	if err != nil {
		return user, fmt.Errorf("Could not parse the bytes of the body: %s", err.Error())
	}

	return user, nil
}
