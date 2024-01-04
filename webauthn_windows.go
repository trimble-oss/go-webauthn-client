//go:build windows
// +build windows

// A simple wrapper around the Windows webauthn DLL
package webauthn

// Based on https://learn.microsoft.com/en-us/windows/win32/api/webauthn/ and https://github.com/microsoft/webauthn
// Usage examples:
// Chromium: https://github.com/chromium/chromium/blob/498ca8aeec113ee0e16136ae5e81c8ac8cd69898/device/fido/win/webauthn_api.cc
// Yubico python-fido2: https://github.com/Yubico/python-fido2/blob/main/fido2/win_api.py
// DelphiFido2: https://github.com/mikerabat/DelphiFido2/blob/master/webauthn.pas

/*
#cgo CFLAGS: -g
#include <Windows.h>
#include <Winuser.h>
#include "windows/webauthn/webauthn.h"
*/
import "C"

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	win_authn_dll                                     = syscall.NewLazyDLL("webauthn.dll")
	procApiVersionNumber                              = win_authn_dll.NewProc("WebAuthNGetApiVersionNumber")
	procIsUserVerifyingPlatformAuthenticatorAvailable = win_authn_dll.NewProc("WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable")
	procAuthenticatorGetAssertion                     = win_authn_dll.NewProc("WebAuthNAuthenticatorGetAssertion")
	procWebAuthNFreeAssertion                         = win_authn_dll.NewProc("WebAuthNFreeAssertion")
	procGetErrorName                                  = win_authn_dll.NewProc("WebAuthNGetErrorName")
)

func getApiVersionNumber() int {
	rv, _, _ := procApiVersionNumber.Call()
	return int(rv)
}

// Authenticate produces an assertion signature representing an assertion by
// the authenticator that the user has consented to a specific transaction, such
// as logging in or completing a purchase.
func Authenticate(challengeNonce, rpId string, timeoutMs int) (*AuthenticateResponse, error) {
	client := ClientData{
		Type:        "webauthn.get",
		Challenge:   challengeNonce,
		Origin:      "https://" + rpId,
		CrossOrigin: false,
	}
	client_data_json, err := json.Marshal(client)
	if err != nil {
		return nil, err
	}
	var client_data = C.WEBAUTHN_CLIENT_DATA{
		dwVersion:        C.WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
		cbClientDataJSON: C.DWORD(len(client_data_json)),
		pbClientDataJSON: C.PBYTE(unsafe.Pointer(&client_data_json[0])), // N.B: UTF-8
		pwszHashAlgId:    C.LPCWSTR(unsafe.Pointer(windows.StringToUTF16Ptr("SHA-256"))),
	}

	get_assert_options := C.WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS{
		dwVersion:                     C.WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION,
		dwTimeoutMilliseconds:         C.DWORD(timeoutMs),
		dwUserVerificationRequirement: C.WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
	}

	var assertion_result C.PWEBAUTHN_ASSERTION

	window_handle := C.GetForegroundWindow()
	// https://learn.microsoft.com/en-us/windows/win32/api/webauthn/nf-webauthn-webauthnauthenticatorgetassertion
	rv, _, _ := procAuthenticatorGetAssertion.Call(
		uintptr(unsafe.Pointer(window_handle)),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(rpId))),
		uintptr(unsafe.Pointer(&client_data)),
		uintptr(unsafe.Pointer(&get_assert_options)),
		uintptr(unsafe.Pointer(&assertion_result)),
	)
	if rv != 0 {
		return nil, errors.New(getErrorName(rv))
	}

	resp := AuthenticateResponse{
		ClientData: base64.StdEncoding.EncodeToString(client_data_json),
		SignatureData: base64.StdEncoding.EncodeToString(C.GoBytes(
			unsafe.Pointer(assertion_result.pbSignature),
			C.int(assertion_result.cbSignature),
		)),
		AuthenticatorData: base64.StdEncoding.EncodeToString(C.GoBytes(
			unsafe.Pointer(assertion_result.pbAuthenticatorData),
			C.int(assertion_result.cbAuthenticatorData),
		)),
	}

	rv, _, _ = procWebAuthNFreeAssertion.Call(uintptr(unsafe.Pointer(assertion_result)))

	return &resp, nil
}

func getErrorName(hr uintptr) string {
	procGetErrorName.Call(hr)
	return ""
}
