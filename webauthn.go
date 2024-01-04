//go:build !windows
// +build !windows

package webauthn

import "errors"

func Authenticate(challengeNonce, rpId string, timeoutMs int) (*AuthenticateResponse, error) {
	return nil, errors.New("System library webauthn authentication is not supported on this platform")
}
