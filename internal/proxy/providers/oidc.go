package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	log "github.com/buzzfeed/sso/internal/pkg/logging"
	oidc "github.com/coreos/go-oidc"
	"github.com/datadog/datadog-go/statsd"
	"golang.org/x/oauth2"
)

var (
	// This is a compile-time check to make sure our types correctly implement the interface:
	// https://medium.com/@matryer/golang-tip-compile-time-checks-to-ensure-your-type-satisfies-an-interface-c167afed3aae
	_ Provider = &OIDCProvider{}
)

// Errors
// var (
// 	ErrMissingRefreshToken     = errors.New("missing refresh token")
// 	ErrAuthProviderUnavailable = errors.New("auth provider unavailable")
// )

// var userAgentString string

// OIDCProvider holds the data associated with the OIDCProviders
// necessary to implement a SSOProvider interface.
type OIDCProvider struct {
	*ProviderData

	Verifier     *oidc.IDTokenVerifier
	StatsdClient *statsd.Client
}

func init() {
	version := os.Getenv("RIG_IMAGE_VERSION")
	if version == "" {
		version = "HEAD"
	} else {
		version = strings.Trim(version, `"`)
	}
	userAgentString = fmt.Sprintf("sso_proxy/%s", version)
}

// NewOIDCProvider instantiates a new SSOProvider with provider data and
// a statsd client.
func NewOIDCProvider(p *ProviderData, sc *statsd.Client) *OIDCProvider {
	p.ProviderName = "OIDC"
	base := p.ProviderURL
	provider, err := oidc.NewProvider(context.Background(), "https://semaku.eu.auth0.com/")
	if err != nil {
		// return err
	}

	p.SignInURL = base.ResolveReference(&url.URL{Path: "/authorize"})
	p.SignOutURL = base.ResolveReference(&url.URL{Path: "/authorize"})
	p.RedeemURL = base.ResolveReference(&url.URL{Path: "/oauth/token"})
	p.RefreshURL = base.ResolveReference(&url.URL{Path: "/oauth/token"})
	p.ValidateURL = base.ResolveReference(&url.URL{Path: "/userinfo"})
	p.ProfileURL = base.ResolveReference(&url.URL{Path: "/userinfo"})
	return &OIDCProvider{
		ProviderData: p,
		StatsdClient: sc,
		Verifier: provider.Verifier(&oidc.Config{
			ClientID: p.ClientID,
		}),
	}
}

func (p *OIDCProvider) withinGracePeriod(s *SessionState) bool {
	if s.GracePeriodStart.IsZero() {
		s.GracePeriodStart = time.Now()
	}
	return s.GracePeriodStart.Add(p.GracePeriodTTL).After(time.Now())
}

// Redeem takes a redirectURL and code and redeems the SessionState
func (p *OIDCProvider) Redeem(redirectURL, code string) (*SessionState, error) {
	ctx := context.Background()
	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
		RedirectURL: redirectURL,
	}
	token, err := c.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %v", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("token response did not contain an id_token")
	}

	// Parse and verify ID Token payload.
	idToken, err := p.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("could not verify id_token: %v", err)
	}

	// Extract custom claims.
	var claims struct {
		Email    string `json:"email"`
		Verified *bool  `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse id_token claims: %v", err)
	}

	if claims.Email == "" {
		return nil, fmt.Errorf("id_token did not contain an email")
	}
	if claims.Verified != nil && !*claims.Verified {
		return nil, fmt.Errorf("email in id_token (%s) isn't verified", claims.Email)
	}

	user := strings.Split(claims.Email, "@")[0]

	return &SessionState{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,

		RefreshDeadline:  token.Expiry,
		LifetimeDeadline: extendDeadline(p.SessionLifetimeTTL),
		ValidDeadline:    extendDeadline(p.SessionValidTTL),

		Email: claims.Email,
		User:  user,
	}, nil
}

// ValidateGroup does a GET request to the profile url and returns true if the user belongs to
// an authorized group.
func (p *OIDCProvider) ValidateGroup(email string, allowedGroups []string) ([]string, bool, error) {
	logger := log.NewLogEntry()

	logger.WithUser(email).WithAllowedGroups(allowedGroups).Info("validating groups")
	inGroups := []string{}
	if len(allowedGroups) == 0 {
		return inGroups, true, nil
	}

	userGroups, err := p.UserGroups(email, allowedGroups)
	if err != nil {
		return nil, false, err
	}

	allowed := false
	for _, userGroup := range userGroups {
		for _, allowedGroup := range allowedGroups {
			if userGroup == allowedGroup {
				inGroups = append(inGroups, userGroup)
				allowed = true
			}
		}
	}

	return inGroups, allowed, nil
}

// UserGroups takes an email and returns the UserGroups for that email
func (p *OIDCProvider) UserGroups(email string, groups []string) ([]string, error) {
	params := url.Values{}
	params.Add("email", email)
	params.Add("client_id", p.ClientID)
	params.Add("groups", strings.Join(groups, ","))

	req, err := newRequest("GET", fmt.Sprintf("%s?%s", p.ProfileURL.String(), params.Encode()), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Client-Secret", p.ClientSecret)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		if isProviderUnavailable(resp.StatusCode) {
			return nil, ErrAuthProviderUnavailable
		}
		return nil, fmt.Errorf("got %d from %q %s", resp.StatusCode, p.ProfileURL.String(), body)
	}

	var jsonResponse struct {
		Email  string   `json:"email"`
		Groups []string `json:"groups"`
	}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return nil, err
	}

	return jsonResponse.Groups, nil
}

// RefreshSession takes a SessionState and allowedGroups and refreshes the session access token,
// returns `true` on success, and `false` on error
func (p *OIDCProvider) RefreshSession(s *SessionState, allowedGroups []string) (bool, error) {
	logger := log.NewLogEntry()

	if s.RefreshToken == "" {
		return false, ErrMissingRefreshToken
	}

	newToken, duration, err := p.redeemRefreshToken(s.RefreshToken)
	if err != nil {
		// When we detect that the auth provider is not explicitly denying
		// authentication, and is merely unavailable, we refresh and continue
		// as normal during the "grace period"
		if err == ErrAuthProviderUnavailable && p.withinGracePeriod(s) {
			tags := []string{"action:refresh_session", "error:redeem_token_failed"}
			p.StatsdClient.Incr("provider_error_fallback", tags, 1.0)
			s.RefreshDeadline = extendDeadline(p.SessionValidTTL)
			return true, nil
		}
		return false, err
	}

	inGroups, validGroup, err := p.ValidateGroup(s.Email, allowedGroups)
	if err != nil {
		// When we detect that the auth provider is not explicitly denying
		// authentication, and is merely unavailable, we refresh and continue
		// as normal during the "grace period"
		if err == ErrAuthProviderUnavailable && p.withinGracePeriod(s) {
			tags := []string{"action:refresh_session", "error:user_groups_failed"}
			p.StatsdClient.Incr("provider_error_fallback", tags, 1.0)
			s.RefreshDeadline = extendDeadline(p.SessionValidTTL)
			return true, nil
		}
		return false, err
	}
	if !validGroup {
		return false, errors.New("Group membership revoked")
	}
	s.Groups = inGroups

	s.AccessToken = newToken
	s.RefreshDeadline = extendDeadline(duration)
	s.GracePeriodStart = time.Time{}
	logger.WithUser(s.Email).WithRefreshDeadline(s.RefreshDeadline).Info("refreshed session access token")
	return true, nil
}

func (p *OIDCProvider) redeemRefreshToken(refreshToken string) (token string, expires time.Duration, err error) {
	// https://developers.google.com/identity/protocols/OAuth2WebServer#refresh
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("refresh_token", refreshToken)
	params.Add("grant_type", "refresh_token")
	var req *http.Request
	req, err = newRequest("POST", p.RefreshURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != http.StatusCreated {
		if isProviderUnavailable(resp.StatusCode) {
			err = ErrAuthProviderUnavailable
		} else {
			err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RefreshURL.String(), body)
		}
		return
	}

	var data struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return
	}
	token = data.AccessToken
	expires = time.Duration(data.ExpiresIn) * time.Second
	return
}

// ValidateSessionState takes a sessionState and allowedGroups and validates the session state
func (p *OIDCProvider) ValidateSessionState(s *SessionState, allowedGroups []string) bool {
	return validateToken(p, s.AccessToken, nil)
}
