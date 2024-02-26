package webauthn

import (
	"testing"
)

func TestAuthenticateOkta(t *testing.T) {
	_, _ = Authenticate("aGVsbG8sIHdvcmxk", "trimble.okta.com", 1000)
}
