package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

var (
	ErrLDAPNotConfigured     = errors.New("LDAP authentication is not configured")
	ErrLDAPInvalidCredential = errors.New("invalid LDAP username or password")
	ErrLDAPUserNotFound      = errors.New("LDAP user not found")
)

type LDAPIdentity struct {
	Username string
	Email    string
	Name     string
}

type LDAPAuthenticator interface {
	Authenticate(ctx context.Context, username, password string) (LDAPIdentity, error)
}

type LDAPConfig struct {
	URL              string
	BaseDN           string
	BindDN           string
	BindPassword     string
	SearchAttributes []string
	EmailAttribute   string
	NameAttribute    string
	Timeout          time.Duration
}

func LDAPConfigFromEnv() LDAPConfig {
	attrs := splitLDAPAttributes(os.Getenv("LDAP_SEARCH_ATTRIBUTES"))
	if len(attrs) == 0 {
		attrs = []string{"uid", "cn", "mail"}
	}
	return LDAPConfig{
		URL:              strings.TrimSpace(os.Getenv("LDAP_URL")),
		BaseDN:           strings.TrimSpace(os.Getenv("LDAP_BASE_DN")),
		BindDN:           strings.TrimSpace(os.Getenv("LDAP_BIND_DN")),
		BindPassword:     os.Getenv("LDAP_BIND_PASSWORD"),
		SearchAttributes: attrs,
		EmailAttribute:   envOrDefault("LDAP_EMAIL_ATTRIBUTE", "mail"),
		NameAttribute:    envOrDefault("LDAP_NAME_ATTRIBUTE", "cn"),
		Timeout:          5 * time.Second,
	}
}

func (c LDAPConfig) Enabled() bool {
	return c.URL != "" && c.BaseDN != "" && c.BindDN != "" && c.BindPassword != ""
}

type LDAPClient struct{ config LDAPConfig }

func NewLDAPClient(config LDAPConfig) *LDAPClient { return &LDAPClient{config: config} }

func (c *LDAPClient) Authenticate(ctx context.Context, username, password string) (LDAPIdentity, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return LDAPIdentity{}, ErrLDAPInvalidCredential
	}
	if !c.config.Enabled() {
		return LDAPIdentity{}, ErrLDAPNotConfigured
	}

	conn, err := c.dial(ctx)
	if err != nil {
		return LDAPIdentity{}, fmt.Errorf("connect to LDAP: %w", err)
	}
	defer conn.Close()
	if err := conn.Bind(c.config.BindDN, c.config.BindPassword); err != nil {
		return LDAPIdentity{}, fmt.Errorf("bind LDAP service account: %w", err)
	}

	filter := ldapUserFilter(c.config.SearchAttributes, username)
	attributes := uniqueStrings(append([]string{c.config.EmailAttribute, c.config.NameAttribute}, c.config.SearchAttributes...))
	result, err := conn.Search(ldap.NewSearchRequest(c.config.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, int(c.config.Timeout.Seconds()), false, filter, attributes, nil))
	if err != nil {
		return LDAPIdentity{}, fmt.Errorf("search LDAP user: %w", err)
	}
	if len(result.Entries) != 1 {
		return LDAPIdentity{}, ErrLDAPUserNotFound
	}

	entry := result.Entries[0]
	if err := conn.Bind(entry.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return LDAPIdentity{}, ErrLDAPInvalidCredential
		}
		return LDAPIdentity{}, fmt.Errorf("bind LDAP user: %w", err)
	}
	return LDAPIdentity{Username: username, Email: strings.ToLower(strings.TrimSpace(entry.GetAttributeValue(c.config.EmailAttribute))), Name: strings.TrimSpace(entry.GetAttributeValue(c.config.NameAttribute))}, nil
}

func ldapUserFilter(attributes []string, username string) string {
	escaped := ldap.EscapeFilter(username)
	parts := make([]string, 0, len(attributes))
	for _, attr := range attributes {
		parts = append(parts, "("+attr+"="+escaped+")")
	}
	return "(|" + strings.Join(parts, "") + ")"
}

func (c *LDAPClient) dial(ctx context.Context) (*ldap.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	timeout := c.config.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}
	return ldap.DialURL(c.config.URL, ldap.DialWithDialer(dialer))
}

func splitLDAPAttributes(raw string) []string {
	var result []string
	for _, value := range strings.Split(raw, ",") {
		value = strings.TrimSpace(value)
		if value != "" {
			result = append(result, value)
		}
	}
	return uniqueStrings(result)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
