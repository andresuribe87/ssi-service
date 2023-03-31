package integration

import (
	"bytes"
	"context"
	_ "embed"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	did2 "github.com/tbd54566975/ssi-service/pkg/service/did"
	"golang.org/x/oauth2"
)

func TestAuthorizationCodeFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	issuerIdentifier := "http://localhost:8080/oidc/issuer"
	obtainCredentialIssuerMetadatafromIssuer(t, issuerIdentifier)
}
func TestObtainCredentialIssuerMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// Run hydra first, from the hydra folder.
	// docker-compose -f quickstart.yml -f quickstart-postgres.yml up --build
	// Then run ssi-service
	// mage -v run

	// We start with the Credential Issuer Identifier
	issuerIdentifier := "http://localhost:8080/oidc/issuer"
	// For local testing
	// issuerIdentifier := "http://localhost:3001/oidc/issuer"

	// TODO: finish this! retrieve the JSON document
	credentialIssuerMetadata := obtainCredentialIssuerMetadatafromIssuer(t, issuerIdentifier)

	// Fetch the auth server metadata via from credentialIssuerMetadata.AuthorizationServer, /.well-known/oauth-authorization-server
	oauthAuthServer := "http://localhost:4444"
	oauthAdminServer := "http://localhost:4445"

	jsonOauthMetadata, err := get(oauthAuthServer + "/.well-known/openid-configuration")
	require.NoError(t, err)
	require.NotEmpty(t, jsonOauthMetadata)

	var oauthServerMetadata map[string]any
	require.NoError(t, json.Unmarshal([]byte(jsonOauthMetadata), &oauthServerMetadata))
	require.NotEmpty(t, oauthServerMetadata["authorization_endpoint"])

	ts := httptest.NewServer(http.HandlerFunc(authorizationCodeCallback))
	defer ts.Close()

	// Create an oauth client with the scope for the credential endpoint
	createOauthClientRequest := map[string]any{
		"response_types": []string{"code"},
		"scope":          "some.Credential.Type",
		"redirect_uris":  []string{ts.URL},
		"grant_types": []string{
			"authorization_code",
			"refresh_token",
		},
	}
	createOauthClientRequestBytes, err := json.Marshal(createOauthClientRequest)
	require.NoError(t, err)
	createClientResponse, err := http.Post(
		oauthAdminServer+"/admin/clients",
		"application/json",
		bytes.NewReader(createOauthClientRequestBytes),
	)
	require.NoError(t, err)
	createClientResponseBody, err := io.ReadAll(createClientResponse.Body)
	require.NoError(t, err)
	require.NotEmpty(t, createClientResponseBody)
	require.True(t, is2xxResponse(createClientResponse.StatusCode))
	var createClientResponseMap map[string]any
	require.NoError(t, json.Unmarshal(createClientResponseBody, &createClientResponseMap))

	// Overall flow at: https://www.ory.sh/docs/hydra/login-consent-flow#the-flow-steps
	// Also in https://www.ory.sh/docs/hydra/concepts/login#initiating-the-oauth-20--openid-connect-flow

	// 1. Make an authorization request to authServerMetadata.authorization_endpoint
	conf := &oauth2.Config{
		ClientID:     createClientResponseMap["client_id"].(string),
		ClientSecret: createClientResponseMap["client_secret"].(string),
		Scopes:       []string{createClientResponseMap["scope"].(string)},
		Endpoint: oauth2.Endpoint{
			TokenURL: oauthServerMetadata["token_endpoint"].(string),
			AuthURL:  oauthServerMetadata["authorization_endpoint"].(string),
		},
		RedirectURL: ts.URL,
	}
	authCodeURL := conf.AuthCodeURL("some_state")
	// TODO: Maybe add one of the prompt={login,consent}

	// Do a get to that auth URL, which will should redirect to the login flow with a challenge.
	// We simulate the login system having authenticated the user, and tell hydra about it via https://www.ory.sh/docs/reference/api#tag/oAuth2/operation/acceptOAuth2LoginRequest
	// Note that we need to take the login_challenge param from the Location header

	// We want to maintain the cookies
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	httpClient := &http.Client{
		Jar: jar,
	}
	authCodeResp, err := httpClient.Get(authCodeURL)
	require.NoError(t, err)

	// 2. Redirected to the login provider's page with a `login_challenge` parameter.
	loginChallenge := authCodeResp.Request.URL.Query().Get("login_challenge")
	require.NotEmpty(t, loginChallenge)

	// 3.a Mimic the login provider telling Ory that the login accept was successful. I.e. user authentication.
	acceptLoginRequest, err := http.NewRequest(
		http.MethodPut,
		oauthAdminServer+"/oauth2/auth/requests/login/accept?login_challenge="+loginChallenge,
		bytes.NewBuffer([]byte(`{"subject":"foo@bar.com"}`)))
	require.NoError(t, err)
	acceptLoginRequest.Header.Set("Content-Type", "application/json")

	acceptLoginResponse, err := httpClient.Do(acceptLoginRequest)
	require.NoError(t, err)
	output, err := io.ReadAll(acceptLoginResponse.Body)
	require.NoError(t, err)
	require.NotEmpty(t, output)

	// 3.b. The login provider should redirect to with the `login_verifier` parameter.
	var acceptLoginResp map[string]any
	require.NoError(t, json.Unmarshal([]byte(output), &acceptLoginResp))
	// redirect_to is something like
	// http://127.0.0.1:4444/oauth2/auth?client_id=dc081a6b-ffba-4ba6-9cad-87ed53914b65&login_verifier=9af1622e63384bb5b41194acfea0402e&redirect_uri=http%3A%2F%2Flocalhost%3A3001%2Fcallback&response_type=code&scope=some_access_scope&state=some_state
	u, err := url.ParseQuery(acceptLoginResp["redirect_to"].(string))
	require.NoError(t, err)
	require.NotEmpty(t, u.Get("login_verifier"))

	// 4. Ory should reply  by redirecting to the consent provider
	req, err := http.NewRequest(http.MethodGet, acceptLoginResp["redirect_to"].(string), nil)
	require.NoError(t, err)

	acceptLoginRedirectResp, err := httpClient.Do(req)
	require.NoError(t, err)

	acceptLoginRedirectRespBody, err := io.ReadAll(acceptLoginRedirectResp.Body)
	require.NoError(t, err)
	require.NotEmpty(t, acceptLoginRedirectRespBody)

	// 5. Consent provider shows a UI

	// 6. Mimic consent provider telling Ory which permissions the user authorizer.
	consentChallenge := acceptLoginRedirectResp.Request.URL.Query().Get("consent_challenge")
	require.NotEmpty(t, consentChallenge)
	consentRequest, err := http.NewRequest(
		http.MethodPut,
		oauthAdminServer+"/oauth2/auth/requests/consent/accept?consent_challenge="+consentChallenge,
		bytes.NewBuffer([]byte(`{"grant_scope":["some_access_scope"]}`)))
	require.NoError(t, err)

	consentResp, err := httpClient.Do(consentRequest)
	require.NoError(t, err)

	consentRespBody, err := io.ReadAll(consentResp.Body)
	require.NoError(t, err)
	require.NotEmpty(t, consentRespBody)

	var consentRespJSON map[string]any
	require.NoError(t, json.Unmarshal(consentRespBody, &consentRespJSON))

	consentRedirectReq, err := http.NewRequest(http.MethodGet, consentRespJSON["redirect_to"].(string), nil)
	require.NoError(t, err)

	// And this should actually send you back to the callback initially defined.
	consentRedirectResp, err := httpClient.Do(consentRedirectReq)
	require.NoError(t, err)

	// Extract the Authorization Code from the Authorization Response.
	// The code is delivered via query components of redirection
	authorizationCode := consentRedirectResp.Request.URL.Query().Get("code")
	require.NotEmpty(t, authorizationCode)

	// Send a Token Request to authServerMetadata.token_endpoint with the auth_code from above.
	token, err := conf.Exchange(context.Background(), authorizationCode)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Extract access_token from TokenResponse.
	authorizedClient := conf.Client(context.Background(), token)
	cNonce := token.Extra("c_nonce").(string)

	// Send the credential request (MUST be TLS) to credentialIssuerMetadata.CredentialEndpoint with access_token. Must be signed
	credentialEndpoint := credentialIssuerMetadata["credential_endpoint"].(string)
	didJSON, err := CreateDIDKey()
	require.NoError(t, err)
	proofJWT := createProofJWT(t, cNonce, conf.ClientID, credentialEndpoint, didJSON)
	credentialRequest := credentialRequest{
		Format: "jwt_vc_json",
		Proof: proof{
			ProofType: "jwt",
			JWT:       string(proofJWT),
		},
	}
	credentialRequestBytes, err := json.Marshal(credentialRequest)
	require.NoError(t, err)

	credentialResp, err := authorizedClient.Post(credentialEndpoint, "application/json", bytes.NewReader(credentialRequestBytes))
	require.NoError(t, err)
	require.NotEmpty(t, credentialResp)

	credentialRespBody, err := io.ReadAll(credentialResp.Body)
	require.NoError(t, err)
	var parseCredentialResponse credentialResponse
	require.NoError(t, json.Unmarshal(credentialRespBody, &parseCredentialResponse))

	assert.Equal(t, "jwt_vc_json", parseCredentialResponse.Format)
	assert.NotEmpty(t, parseCredentialResponse.Credential)
	assert.NotEmpty(t, parseCredentialResponse.AcceptanceToken)
	assert.Equal(t, cNonce, parseCredentialResponse.ClientNonce)
	assert.Greater(t, parseCredentialResponse.ClientNonceExpiresIn, 60, "expiration should be later than 60 seconds")

	// with the credentialSubjects private key.

	// Review that the credential was actually issued.
}

type credentialRequest struct {
	Format string `json:"format"`
	Proof  proof  `json:"proof"`
}
type proof struct {
	ProofType string `json:"proof_type"`
	JWT       string `json:"jwt"`
}
type credentialResponse struct {
	Format               string `json:"format"`
	Credential           any    `json:"credential"`
	AcceptanceToken      string `json:"acceptance_token"`
	ClientNonce          string `json:"c_nonce"`
	ClientNonceExpiresIn int    `json:"c_nonce_expires_in"`
}

type AuthCodeGrant struct {
	IssuerState string `json:"issuer_state,omitempty"`
}

type PreAuthCodeGrant struct {
	PreAuthorizedCode string `json:"pre-authorized_code" validate:"required"`
	UserPinRequired   bool   `json:"user_pin_required,omitempty"`
}

// Use case
// I have an AS, and PI of users. E.g. I am a university. Now I want to issue a university degree credential.

// Solution with SSI
// 1. Run SSI
// 2. Create a credential template
// 3. There is a credential offer endpoint, hosted by SSI.

type Grants struct {
	AuthorizationCode AuthCodeGrant    `json:"authorization_code,omitempty"`
	PreAuthorizedCode PreAuthCodeGrant `json:"urn:ietf:params:oauth:grant-type:pre-authorized_code,omitempty"`
}

type CredentialOffer struct {
	// CredentialIssuer is the URL of the Credential Issuer that the Wallet is requested to obtain one or more Credentials from. This is a required field.
	CredentialIssuer string `json:"credential_issuer,omitempty"`

	// Credentials is a JSON array where each entry is a JSON object or string. Each JSON object contains data related to a certain credential type that the Wallet may request. The string value of each entry must be one of the id values in one of the objects in the `credentials_supported` Credential Issuer metadata parameter. This is a required field.
	Credentials []any `json:"credentials,omitempty"`

	// Grants is a JSON object indicating to the Wallet the Grant Types that the Credential Issuer's AS is prepared to process for this credential offer. Each grant is represented by a key and an object. The key value is the Grant Type identifier, and the object may contain parameters either determining the way the Wallet must use the particular grant and/or parameters the Wallet must send with the respective request(s). If this field is not present or empty, the Wallet must determine the Grant Types the Credential Issuer's AS supports using the respective metadata. When multiple grants are present, it's at the Wallet's discretion which one to use. This field is optional.
	Grants Grants `json:"grants,omitempty"`
}

type CredentialOfferRequest struct {
	// A JSON object with the Credential Offer parameters. MUST NOT be present when credential_offer_uri parameter is present.
	CredentialOffer CredentialOffer `json:"credential_offer,omitempty"`

	// A URL using the https scheme referencing a resource containing a JSON object with the Credential Offer parameters. MUST NOT be present when credential_offer parameter is present.
	CredentialOfferURI string `json:"credential_offer_uri"`
}

func createProofJWT(t *testing.T, nonce string, clientID string, credentialEndpoint string, didJSON string) []byte {
	token, err := jwt.NewBuilder().Issuer(clientID).Audience([]string{credentialEndpoint}).IssuedAt(time.Now()).Build()
	require.NoError(t, err)
	require.NoError(t, token.Set("nonce", nonce))

	var didResponse did2.CreateDIDResponse
	require.NoError(t, json.Unmarshal([]byte(didJSON), &didResponse))

	didPrivKeyBytes, err := base58.Decode(didResponse.PrivateKeyBase58)
	require.NoError(t, err)

	didPrivKey, err := crypto.BytesToPrivKey(didPrivKeyBytes, crypto.Ed25519)
	require.NoError(t, err)

	s, err := crypto.NewJWTSigner(didResponse.DID.ID, didPrivKey)
	require.NoError(t, err)

	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set(jws.TypeKey, "openid4vci-proof+jwt"))
	require.NoError(t, hdrs.Set(jws.KeyIDKey, s.KeyID()))

	jwtBytes, err := jwt.Sign(token, jwa.SignatureAlgorithm(s.GetSigningAlgorithm()), s.Key, jwt.WithHeaders(hdrs))
	require.NoError(t, err)

	return jwtBytes
}

func obtainCredentialIssuerMetadatafromIssuer(t *testing.T, issuerIdentifier string) map[string]any {
	jsonOutput, err := get(issuerIdentifier + "/.well-known/openid-credential-issuer")
	require.NoError(t, err)
	require.NotEmpty(t, jsonOutput)

	var credentialIssuerMetadata map[string]any
	require.NoError(t, json.Unmarshal([]byte(jsonOutput), &credentialIssuerMetadata))
	return credentialIssuerMetadata
}

func authorizationCodeCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		panic("empty code")
	}
	scope := r.URL.Query().Get("scope")
	if scope == "" {
		panic("empty scope")
	}
	state := r.URL.Query().Get("state")
	if state == "" {
		panic("empty state")
	}
}

func TestPreAuthorizedCredentialIssuance(t *testing.T) {

	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// Assuming that the information is ready. Query the CredentialOffer endpoint.

	// Get the issuerIdentifier from the CredentialOffer response, and the pre-auth code, and whether pin is required.

	// Retrieve metadata from the issuerIdentifier.

	// Wait for the PIN to be communicated.

	// Send a token request to authServerMetadata.token_endpoint with the pre-auth code and the PIN received.

	// Extract access_token from TokenResponse.

	// Send the credential request to credentialIssuerMetadata.CredentialEndpoint with access_token. Must be signed
	// with the credentialSubjects private key.

	// Review that the credential was actually issued.
}

func TestPresentation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// This test is run as if the wallet is running it. Note that the spec assumes that wallet can respond to
	// oauth authorization style requests. Additionally, the spec assumes that the "client", is the Verifier.

	// So let's start.

	// The verifier sends an authorization request, specifying presentation_definition_uri/client_metadata_uri

	// Download the client_metadata, which has the fields in https://www.rfc-editor.org/rfc/rfc7591.html#section-2.
	// This can also come from another protocol

	// client_metadata should have vp_formats

	// Create a get authorization request for verifiable presentation. Perhaps layer it on top of the presentation_definition
	// endpoint.

	// Fetch the presentation_definition from the uri in request.presentation_definition_uri
	// request.response_type must be == vp_token

	// Assemble a response depending on the response_type parameter value.

	// send the response to request.redirect_uri

}
