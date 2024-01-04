package webauthn

// Based on https://github.com/marshallbrekka/go-u2fhost/blob/master/types.go

// A response from an Authenticate operation.
// The response fields are typically passed back to the server.
type AuthenticateResponse struct {
	ClientData        string `json:"clientData"`
	SignatureData     string `json:"signatureData"`
	AuthenticatorData string `json:"authenticatorData,omitempty"`
}

// https://www.w3.org/TR/webauthn-2/#dictdef-tokenbinding
type TokenBinding struct {
	Status string `json:"status"` // SHOULD be "present" or "supported"
	Id     string `json:"id"`     // MUST be a base64url encoding of the Token Binding ID that was used when communicating with the Relying Party.
}

// https://www.w3.org/TR/webauthn-2/#dictionary-client-data
type ClientData struct {
	Type         string        `json:"type"`
	Challenge    string        `json:"challenge"`
	Origin       string        `json:"origin"`
	CrossOrigin  bool          `json:"crossOrigin"`
	TokenBinding *TokenBinding `json:"tokenBinding,omitempty"`
}
