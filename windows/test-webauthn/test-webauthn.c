#include <stdio.h>
#include <Windows.h>
#include <Winuser.h>

#include "../webauthn/webauthn.h"

int main (int argc, int** argv) {
    HRESULT result;

    printf("Windows Webauthn API version: %d\n", WebAuthNGetApiVersionNumber());

    WEBAUTHN_GET_CREDENTIALS_OPTIONS get_creds_options = {
        .dwVersion=WEBAUTHN_GET_CREDENTIALS_OPTIONS_CURRENT_VERSION
    };
    WEBAUTHN_CREDENTIAL_DETAILS_LIST *credentials;
    result = WebAuthNGetPlatformCredentialList(&get_creds_options, &credentials);

    if (result != S_OK) {
        wprintf(WebAuthNGetErrorName(result));
        return -1;
    }

    printf("Credentials (%d):\n\n", credentials->cCredentialDetails);

    for (int i = 0; i < credentials->cCredentialDetails; i++) {
        printf("Index: %d\n", i);
        PWEBAUTHN_CREDENTIAL_DETAILS credential = credentials->ppCredentialDetails[i];
        printf("ID: ");
        for (int j = 0; j < credential->cbCredentialID; j++) {
            printf("%02X", credential->pbCredentialID[j]);
        }
        printf("\n");

        PWEBAUTHN_RP_ENTITY_INFORMATION rp_info = credential->pRpInformation;
        printf("Relying Party information:\n");
        wprintf(L"  ID:   %lls\n", rp_info->pwszId);
        wprintf(L"  Name: %lls\n", rp_info->pwszName);
        wprintf(L"  Icon: %lls\n", rp_info->pwszIcon);

        PWEBAUTHN_USER_ENTITY_INFORMATION user_info = credential->pUserInformation;
        printf("User information:\n");
        printf("  ID:   ");
        for (int j = 0; j < user_info->cbId; j++) {
            printf("%02X", user_info->pbId[j]);
        }
        printf("\n");
        wprintf(L"  Name:         %lls\n", user_info->pwszName);
        wprintf(L"  Display name: %lls\n", user_info->pwszDisplayName);
        wprintf(L"  Icon:         %lls\n", user_info->pwszIcon);

        printf("Removable: %d\n", credential->bRemovable);
        printf("Backed up: %d\n", credential->bBackedUp);
        printf("\n");
    }

    int index = credentials->cCredentialDetails+1;
    while (index < 0 || index >= credentials->cCredentialDetails) {
        printf("Enter index to test authentication with [0-%d]: ", credentials->cCredentialDetails-1);
        index = getc(stdin) - '0';
    }
    printf("\n");

    PWEBAUTHN_CREDENTIAL_DETAILS credential = credentials->ppCredentialDetails[index];

    // https://www.w3.org/TR/webauthn-2/#dictionary-client-data
    char* client_data_json =
        "{"
            "\"type\":        \"webauthn.get\","
            "\"challenge\":   \"aGVsbG8sIHdvcmxk\"," // This is a (base64-encoded) nonce in a real world scenario
            "\"origin\":      \"test.local\","
            "\"crossOrigin\": false"
        "}";
    
    WEBAUTHN_CLIENT_DATA client_data = {
        .dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        .cbClientDataJSON = strlen(client_data_json),
        .pbClientDataJSON = client_data_json,
        .pwszHashAlgId = L"SHA-256"
    };

    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS get_assert_options = {
        .dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION,
        .dwTimeoutMilliseconds = 1000,
        .dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
    };

    PWEBAUTHN_ASSERTION assertion_result;
    
    HWND window_handle = GetForegroundWindow();
    result = WebAuthNAuthenticatorGetAssertion(window_handle, credential->pRpInformation->pwszId, &client_data, &get_assert_options, &assertion_result);
    if (result != S_OK) {
        wprintf(WebAuthNGetErrorName(result));
        WebAuthNFreePlatformCredentialList(credentials);
        return -1;
    }

    WebAuthNFreePlatformCredentialList(credentials);

    printf("Assertion result:\n");

    printf("Authenticator data: ");
    for (int j = 0; j < assertion_result->cbAuthenticatorData; j++) {
        printf("%02X", assertion_result->pbAuthenticatorData[j]);
    }
    printf("\n");

    printf("Signature: ");
    for (int j = 0; j < assertion_result->cbSignature; j++) {
        printf("%02X", assertion_result->pbSignature[j]);
    }
    printf("\n");

    printf("Credential:\n");
    printf("  ID:   ");
    for (int j = 0; j < assertion_result->Credential.cbId; j++) {
        printf("%02X", assertion_result->Credential.pbId[j]);
    }
    printf("\n");

    wprintf(L"  Type: %lls\n", assertion_result->Credential.pwszCredentialType);

    printf("User ID: ");
    for (int j = 0; j < assertion_result->cbUserId; j++) {
        printf("%02X", assertion_result->pbUserId[j]);
    }
    printf("\n");

    printf("Large blob: ");
    for (int j = 0; j < assertion_result->cbCredLargeBlob; j++) {
        printf("%02X", assertion_result->pbCredLargeBlob[j]);
    }
    printf("\n");

    printf("Large blob status: %d\n", assertion_result->dwCredLargeBlobStatus);

    WebAuthNFreeAssertion(assertion_result);

    return 0;
}
