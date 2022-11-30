package server

import (
	"fmt"
	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/operation"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestPresentationAPI(t *testing.T) {
	builder := exchange.NewPresentationDefinitionBuilder()
	inputDescriptors := []exchange.InputDescriptor{
		{
			ID:      "id",
			Name:    "name",
			Purpose: "purpose",
			Format: &exchange.ClaimFormat{
				JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
			},
			Constraints: &exchange.Constraints{SubjectIsIssuer: exchange.Preferred.Ptr()},
		},
	}
	assert.NoError(t, builder.SetInputDescriptors(inputDescriptors))
	assert.NoError(t, builder.SetName("name"))
	assert.NoError(t, builder.SetPurpose("purpose"))
	pd, err := builder.Build()
	assert.NoError(t, err)

	s, err := storage.NewStorage(storage.Bolt)
	assert.NoError(t, err)

	keyStoreService := testKeyStoreService(t, s)
	didService := testDIDService(t, s, keyStoreService)
	schemaService := testSchemaService(t, s, keyStoreService, didService)

	service, err := presentation.NewPresentationService(config.PresentationServiceConfig{}, s, didService.GetResolver(), schemaService)
	assert.NoError(t, err)

	pRouter, err := router.NewPresentationRouter(service)
	assert.NoError(t, err)

	t.Cleanup(func() {
		_ = s.Close()
		_ = os.Remove(storage.DBFile)
	})

	t.Run("Create, Get, and Delete PresentationDefinition", func(t *testing.T) {
		var createdID string
		{
			// Create returns the expected PD.
			request := router.CreatePresentationDefinitionRequest{
				Name:                   "name",
				Purpose:                "purpose",
				Format:                 nil,
				SubmissionRequirements: nil,
				InputDescriptors:       inputDescriptors,
			}
			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/presentations/definitions", value)
			w := httptest.NewRecorder()

			err = pRouter.CreatePresentationDefinition(newRequestContext(), w, req)
			assert.NoError(t, err)

			var resp router.CreatePresentationDefinitionResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			if diff := cmp.Diff(*pd, resp.PresentationDefinition, cmpopts.IgnoreFields(exchange.PresentationDefinition{}, "ID")); diff != "" {
				t.Errorf("PresentationDefinition mismatch (-want +got):\n%s", diff)
			}

			w.Flush()
			createdID = resp.PresentationDefinition.ID
		}
		{
			// We can get the PD after it's created.
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", createdID), nil)
			w := httptest.NewRecorder()
			assert.NoError(t, pRouter.GetPresentationDefinition(newRequestContextWithParams(map[string]string{"id": createdID}), w, req))

			var resp router.GetPresentationDefinitionResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Equal(t, createdID, resp.PresentationDefinition.ID)
			if diff := cmp.Diff(*pd, resp.PresentationDefinition, cmpopts.IgnoreFields(exchange.PresentationDefinition{}, "ID")); diff != "" {
				t.Errorf("PresentationDefinition mismatch (-want +got):\n%s", diff)
			}

			w.Flush()
		}
		{
			// The PD can be deleted.
			req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", createdID), nil)
			w := httptest.NewRecorder()
			assert.NoError(t, pRouter.DeletePresentationDefinition(newRequestContextWithParams(map[string]string{"id": createdID}), w, req))

			w.Flush()
		}
		{
			// And we cannot get the PD after it's been deleted.
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", createdID), nil)
			w := httptest.NewRecorder()
			assert.Error(t, pRouter.GetPresentationDefinition(newRequestContextWithParams(map[string]string{"id": createdID}), w, req))

			w.Flush()
		}
	})

	t.Run("Create returns error without input descriptors", func(t *testing.T) {
		request := router.CreatePresentationDefinitionRequest{}
		value := newRequestValue(t, request)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/presentations/definitions", value)
		w := httptest.NewRecorder()

		err = pRouter.CreatePresentationDefinition(newRequestContext(), w, req)

		assert.Error(t, err)
		w.Flush()
	})

	t.Run("Get without an ID returns error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", pd.ID), nil)
		w := httptest.NewRecorder()
		assert.Error(t, pRouter.GetPresentationDefinition(newRequestContext(), w, req))
		w.Flush()
	})

	t.Run("Delete without an ID returns error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", pd.ID), nil)
		w := httptest.NewRecorder()
		assert.Error(t, pRouter.DeletePresentationDefinition(newRequestContext(), w, req))
		w.Flush()
	})

	t.Run("Submission endpoints", func(t *testing.T) {
		t.Run("Get non-existing ID returns error", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions/myrandomid", nil)
			w := httptest.NewRecorder()
			assert.Error(t, pRouter.GetSubmission(newRequestContext(), w, req))
		})

		t.Run("Get returns submission after creation", func(t *testing.T) {
			op, def := createDefinitionAndSubmission(t, pRouter)
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/submissions/%s", operation.SubmissionID(op.ID)), nil)
			w := httptest.NewRecorder()

			assert.NoError(t, pRouter.GetSubmission(newRequestContextWithParams(map[string]string{"id": operation.SubmissionID(op.ID)}), w, req))

			var resp router.GetSubmissionResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Equal(t, operation.SubmissionID(op.ID), resp.Submission.ID)
			assert.Equal(t, def.ID, resp.Submission.DefinitionID)
			assert.Equal(t, "unknown", resp.Status)
		})
	})

	t.Run("well formed submission returns operation", func(t *testing.T) {
		definition := createPresentationDefinition(t, pRouter)
		request := createSubmissionRequest(t, definition)

		value := newRequestValue(t, request)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/presentations/submissions", value)
		w := httptest.NewRecorder()

		err = pRouter.CreateSubmission(newRequestContext(), w, req)

		require.NoError(t, err)
		var resp router.Operation
		assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Contains(t, resp.ID, "presentations/submissions/")
		assert.False(t, resp.Done)
		assert.Zero(t, resp.Result)
	})
}

func createDefinitionAndSubmission(t *testing.T, pRouter *router.PresentationRouter) (router.Operation, exchange.PresentationDefinition) {
	definition := createPresentationDefinition(t, pRouter)
	request := createSubmissionRequest(t, definition)

	value := newRequestValue(t, request)
	req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/presentations/submissions", value)
	w := httptest.NewRecorder()

	err := pRouter.CreateSubmission(newRequestContext(), w, req)

	require.NoError(t, err)
	var resp router.Operation
	assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp, definition.PresentationDefinition
}

func createSubmissionRequest(t *testing.T, definition router.CreatePresentationDefinitionResponse) router.CreateSubmissionRequest {
	vc := VerifiableCredential(
		WithIssuer("did:key:z4oJ8bFEFv7E3omhuK5LrAtL29Nmd8heBey9HtJCSvodSb7nrfaMrd6zb7fjYSRxrfSgBSDeM6Bs59KRKFgXSDWJcfcjs"),
		WithCredentialSubject(credential.CredentialSubject{
			"additionalName": "Mclovin",
			"dateOfBirth":    "1987-01-02",
			"familyName":     "Andres",
			"givenName":      "Uribe",
			"id":             "did:web:andresuribe.com",
		}))

	signer0 := getTestVectorKey0Signer(t)
	vcData, err := signing.SignVerifiableCredentialJWT(signer0, vc)
	assert.NoError(t, err)
	ps := exchange.PresentationSubmission{
		ID:           "a30e3b91-fb77-4d22-95fa-871689c322e2",
		DefinitionID: definition.PresentationDefinition.ID,
		DescriptorMap: []exchange.SubmissionDescriptor{
			{
				ID:         "wa_driver_license",
				Format:     string(exchange.JWTVPTarget),
				Path:       "$.verifiableCredential[0]",
				PathNested: nil,
			},
		},
	}
	vp := credential.VerifiablePresentation{
		Context:                []string{credential.VerifiableCredentialsLinkedDataContext},
		ID:                     "a9b575c7-bac2-47e7-a925-c432815ebb4c",
		Holder:                 "did:key:z4oJ8eRi73fvkrXBgqTHZRTropESXLc7Vet8XpJrGUSBZAT2UHvQBYpBEPdAUiyKBi2XC2iFjgtn5Gw2Qd4WXHyj1LxjU",
		Type:                   []string{credential.VerifiablePresentationType},
		PresentationSubmission: ps,
		VerifiableCredential:   []interface{}{keyaccess.JWT(vcData)},
		Proof:                  nil,
	}

	signer1 := getTestVectorKey1Signer(t)
	signed, err := signing.SignVerifiablePresentationJWT(signer1, vp)
	assert.NoError(t, err)

	request := router.CreateSubmissionRequest{SubmissionJWT: keyaccess.JWT(signed)}
	return request
}

func VerifiableCredential(options ...VcOption) credential.VerifiableCredential {
	vc := credential.VerifiableCredential{
		Context:          []string{credential.VerifiableCredentialsLinkedDataContext},
		ID:               "7035a7ec-66c8-4aec-9191-a34e8cf1e82b",
		Type:             []string{credential.VerifiablePresentationType},
		Issuer:           "did:key:z4oJ8bFEFv7E3omhuK5LrAtL29Nmd8heBey9HtJCSvodSb7nrfaMrd6zb7fjYSRxrfSgBSDeM6Bs59KRKFgXSDWJcfcjs",
		IssuanceDate:     "2022-11-07T21:28:57Z",
		ExpirationDate:   "2051-10-05T14:48:00.000Z",
		CredentialStatus: nil,
		CredentialSubject: credential.CredentialSubject{
			"additionalName": "Mclovin",
			"dateOfBirth":    "1987-01-02",
			"familyName":     "Andres",
			"givenName":      "Uribe",
			"id":             "did:web:andresuribe.com",
		},
		CredentialSchema: nil,
		RefreshService:   nil,
		TermsOfUse:       nil,
		Evidence:         nil,
		Proof:            nil,
	}
	for _, o := range options {
		o(&vc)
	}
	return vc
}

func WithCredentialSubject(subject credential.CredentialSubject) VcOption {
	return func(vc *credential.VerifiableCredential) {
		vc.CredentialSubject = subject
	}
}

type VcOption func(verifiableCredential *credential.VerifiableCredential)

func WithIssuer(s string) VcOption {
	return func(vc *credential.VerifiableCredential) {
		vc.Issuer = s
	}
}

func createPresentationDefinition(t *testing.T, pRouter *router.PresentationRouter) router.CreatePresentationDefinitionResponse {
	request := router.CreatePresentationDefinitionRequest{
		Name:                   "name",
		Purpose:                "purpose",
		Format:                 nil,
		SubmissionRequirements: nil,
		InputDescriptors: []exchange.InputDescriptor{
			{
				ID:      "wa_driver_license",
				Name:    "washington state business license",
				Purpose: "some testing stuff",
				Format:  nil,
				Constraints: &exchange.Constraints{
					Fields: []exchange.Field{
						{
							ID: "date_of_birth",
							Path: []string{
								"$.credentialSubject.dateOfBirth",
								"$.credentialSubject.dob",
								"$.vc.credentialSubject.dateOfBirth",
								"$.vc.credentialSubject.dob",
							},
						},
					},
				},
			},
		},
	}
	value := newRequestValue(t, request)
	req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/presentations/definitions", value)
	w := httptest.NewRecorder()

	assert.NoError(t, pRouter.CreatePresentationDefinition(newRequestContext(), w, req))
	var resp router.CreatePresentationDefinitionResponse
	assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

func getTestVectorKey0Signer(t *testing.T) crypto.JWTSigner {
	// AKA the issuers key
	// AKA did:key:z4oJ8bFEFv7E3omhuK5LrAtL29Nmd8heBey9HtJCSvodSb7nrfaMrd6zb7fjYSRxrfSgBSDeM6Bs59KRKFgXSDWJcfcjs
	knownJWK := crypto.PrivateKeyJWK{
		KTY: "EC",
		CRV: "P-256",
		X:   "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
		Y:   "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
		D:   "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk",
	}

	signer, err := crypto.NewJWTSignerFromJWK(knownJWK.KID, knownJWK)
	assert.NoError(t, err)
	return *signer
}

func getTestVectorKey1Signer(t *testing.T) crypto.JWTSigner {
	// AKA the submitter of the presentation
	// AKA did:key:z4oJ8eRi73fvkrXBgqTHZRTropESXLc7Vet8XpJrGUSBZAT2UHvQBYpBEPdAUiyKBi2XC2iFjgtn5Gw2Qd4WXHyj1LxjU
	knownJWK := crypto.PrivateKeyJWK{
		KTY: "EC",
		CRV: "P-256",
		X:   "6HEz8SLP7NgHPGp0bElryiD7u3_cO1EmX-ngsV_yLsI",
		Y:   "QlIYaYyDLxLkybDan9LOSkfGvjzZsrdgAb_nQr_Li5M",
		D:   "7m6c2Axy9OWi7-d9hFVhmMe22vQTfQDL_pG-3WFsjzc",
	}

	signer, err := crypto.NewJWTSignerFromJWK(knownJWK.KID, knownJWK)
	assert.NoError(t, err)
	return *signer
}
