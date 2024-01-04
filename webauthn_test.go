package webauthn

import (
	"testing"
)

func TestGetApiVersionNumber(t *testing.T) {
	getApiVersionNumber()
}

func TestAuthenticateOkta(t *testing.T) {
	_, _ = Authenticate("aGVsbG8sIHdvcmxk", "trimble.okta.com", 1000)
}
