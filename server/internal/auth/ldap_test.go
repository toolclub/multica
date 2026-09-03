package auth

import (
	"reflect"
	"testing"
)

func TestLDAPConfigFromEnv(t *testing.T) {
	t.Setenv("LDAP_URL", " ldap://example.test:389 ")
	t.Setenv("LDAP_BASE_DN", " dc=example,dc=test ")
	t.Setenv("LDAP_BIND_DN", " cn=reader,dc=example,dc=test ")
	t.Setenv("LDAP_BIND_PASSWORD", "secret")
	t.Setenv("LDAP_SEARCH_ATTRIBUTES", "uid, cn,uid, mail")

	got := LDAPConfigFromEnv()
	if !got.Enabled() {
		t.Fatal("complete LDAP configuration should be enabled")
	}
	wantAttrs := []string{"uid", "cn", "mail"}
	if !reflect.DeepEqual(got.SearchAttributes, wantAttrs) {
		t.Fatalf("SearchAttributes = %#v, want %#v", got.SearchAttributes, wantAttrs)
	}
	if got.URL != "ldap://example.test:389" || got.BaseDN != "dc=example,dc=test" {
		t.Fatalf("configuration was not trimmed: %#v", got)
	}
}

func TestLDAPConfigRequiresAllServiceAccountFields(t *testing.T) {
	config := LDAPConfig{URL: "ldap://example.test", BaseDN: "dc=example", BindDN: "cn=reader"}
	if config.Enabled() {
		t.Fatal("LDAP config without bind password must be disabled")
	}
}

func TestLDAPUserFilterEscapesAssertionValue(t *testing.T) {
	got := ldapUserFilter([]string{"uid", "mail"}, `*)(uid=*)`)
	want := `(|(uid=\2a\29\28uid=\2a\29)(mail=\2a\29\28uid=\2a\29))`
	if got != want {
		t.Fatalf("filter = %q, want %q", got, want)
	}
}
