package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	credmodel "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/operation"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/submission"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func TestOperationsAPI(t *testing.T) {
	t.Run("Marks operation as done after reviewing submission", func(tt *testing.T) {
		s := setupTestDB(tt)
		pRouter := setupPresentationRouter(t, s)
		opRouter := setupOperationsRouter(t, s)

		holderSigner, holderDID := getSigner(t)
		definition := createPresentationDefinition(t, pRouter)
		submissionOp := createSubmission(t, pRouter, definition.PresentationDefinition.ID, VerifiableCredential(), holderDID, holderSigner)
		sub := reviewSubmission(t, pRouter, submission.ID(submissionOp.ID))

		createdID := submissionOp.ID
		req := httptest.NewRequest(
			http.MethodPut,
			fmt.Sprintf("https://ssi-service.com/v1/operations/%s", createdID),
			nil)
		w := httptest.NewRecorder()

		err := opRouter.GetOperation(newRequestContextWithParams(map[string]string{"id": createdID}), w, req)

		assert.NoError(t, err)
		var resp router.Operation
		assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.True(t, resp.Done)
		assert.Empty(t, resp.Result.Error)
		data, err := json.Marshal(sub)
		assert.NoError(t, err)
		var responseAsMap map[string]any
		assert.NoError(t, json.Unmarshal(data, &responseAsMap))
		assert.Equal(t, responseAsMap, resp.Result.Response)
	})

	t.Run("GetOperation", func(t *testing.T) {
		t.Run("Returns operation after application", func(tt *testing.T) {
			s := setupTestDB(tt)
			svc, err := operation.NewOperationService(s)
			assert.NoError(tt, err)
			opRouter, err := router.NewOperationRouter(svc)
			assert.NoError(tt, err)
			keyStoreService := testKeyStoreService(t, s)
			didService := testDIDService(t, s, keyStoreService)
			didRouter, err := router.NewDIDRouter(didService)
			assert.NoError(tt, err)
			schemaService := testSchemaService(t, s, keyStoreService, didService)
			credentialService := testCredentialService(t, s, keyStoreService, didService, schemaService)
			mRouter, _ := testManifest(t, s, keyStoreService, didService, credentialService)
			didSvc := testDIDService(t, s, keyStoreService)
			schemaSvc := testSchemaService(t, s, keyStoreService, didSvc)
			schemaRouter, err := router.NewSchemaRouter(schemaSvc)
			assert.NoError(tt, err)
			credSvc := testCredentialService(t, s, keyStoreService, didSvc, schemaSvc)
			credRouter, err := router.NewCredentialRouter(credSvc)
			assert.NoError(tt, err)

			issuerDID := createDID(t, didRouter)
			subjectDID := createDID(t, didRouter)
			schemaResponse := createSchema(t, schemaRouter, issuerDID.DID.ID)
			credData := map[string]any{"licenseType": "WA-DL-CLASS-A"}
			cred := createCredential(t, credRouter, issuerDID.DID.ID, subjectDID.DID.ID, schemaResponse.ID, credData)
			manifest := createManifest(t, mRouter, issuerDID.DID.ID, schemaResponse.ID)
			applicationOp := submitApplication(t, mRouter, manifest, cred.CredentialJWT, subjectDID)

			createdID := applicationOp.ID
			req := httptest.NewRequest(
				http.MethodPut,
				fmt.Sprintf("https://ssi-service.com/v1/operations/%s", createdID),
				nil)
			w := httptest.NewRecorder()

			err = opRouter.GetOperation(newRequestContextWithParams(map[string]string{"id": createdID}), w, req)

			assert.NoError(tt, err)
			var resp router.Operation
			assert.NoError(tt, json.NewDecoder(w.Body).Decode(&resp))
			assert.True(tt, resp.Done)
			assert.Contains(tt, resp.ID, "credentials/responses/")
		})

		t.Run("Returns operation after submission", func(tt *testing.T) {
			s := setupTestDB(tt)
			pRouter := setupPresentationRouter(t, s)
			opRouter := setupOperationsRouter(t, s)

			holderSigner, holderDID := getSigner(t)
			definition := createPresentationDefinition(t, pRouter)
			submissionOp := createSubmission(t, pRouter, definition.PresentationDefinition.ID, VerifiableCredential(), holderDID, holderSigner)

			createdID := submissionOp.ID
			req := httptest.NewRequest(
				http.MethodPut,
				fmt.Sprintf("https://ssi-service.com/v1/operations/%s", createdID),
				nil)
			w := httptest.NewRecorder()

			err := opRouter.GetOperation(newRequestContextWithParams(map[string]string{"id": createdID}), w, req)

			assert.NoError(t, err)
			var resp router.Operation
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.False(t, resp.Done)
			assert.Contains(t, resp.ID, "presentations/submissions/")
		})

		t.Run("Returns error when id doesn't exist", func(tt *testing.T) {
			s := setupTestDB(tt)
			opRouter := setupOperationsRouter(t, s)

			req := httptest.NewRequest(
				http.MethodPut,
				"https://ssi-service.com/v1/operations/some_fake_id",
				nil)
			w := httptest.NewRecorder()

			err := opRouter.GetOperation(newRequestContextWithParams(map[string]string{"id": "some_fake_id"}), w, req)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), "operation not found with id")
		})
	})

	t.Run("GetOperations", func(t *testing.T) {
		t.Run("Returns empty when no operations stored", func(tt *testing.T) {
			s := setupTestDB(tt)
			opRouter := setupOperationsRouter(t, s)

			request := router.GetOperationsRequest{
				Parent: "presentations/submissions",
			}
			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/operations", value)
			w := httptest.NewRecorder()

			assert.NoError(t, opRouter.GetOperations(newRequestContext(), w, req))

			var resp router.GetOperationsResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Empty(t, resp.Operations)
		})

		t.Run("Returns one operation for every submission", func(tt *testing.T) {
			s := setupTestDB(tt)
			pRouter := setupPresentationRouter(t, s)
			opRouter := setupOperationsRouter(t, s)

			def := createPresentationDefinition(t, pRouter)
			holderSigner, holderDID := getSigner(t)
			submissionOp := createSubmission(t, pRouter, def.PresentationDefinition.ID, VerifiableCredential(), holderDID, holderSigner)

			holderSigner2, holderDID2 := getSigner(t)
			submissionOp2 := createSubmission(t, pRouter, def.PresentationDefinition.ID, VerifiableCredential(), holderDID2, holderSigner2)

			request := router.GetOperationsRequest{
				Parent: "presentations/submissions",
			}
			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/operations", value)
			w := httptest.NewRecorder()

			assert.NoError(t, opRouter.GetOperations(newRequestContext(), w, req))

			var resp router.GetOperationsResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			ops := []router.Operation{submissionOp, submissionOp2}
			diff := cmp.Diff(ops, resp.Operations,
				cmpopts.IgnoreFields(exchange.PresentationSubmission{}, "DescriptorMap"),
				cmpopts.SortSlices(func(l, r router.Operation) bool {
					return l.ID < r.ID
				}),
			)
			if diff != "" {
				t.Errorf("Mismatch on submissions (-want +got):\n%s", diff)
			}
		})

		t.Run("Returns operation when filtering to include", func(tt *testing.T) {
			s := setupTestDB(tt)
			pRouter := setupPresentationRouter(t, s)
			opRouter := setupOperationsRouter(t, s)

			def := createPresentationDefinition(t, pRouter)
			holderSigner, holderDID := getSigner(t)
			_ = createSubmission(t, pRouter, def.PresentationDefinition.ID, VerifiableCredential(), holderDID, holderSigner)

			request := router.GetOperationsRequest{
				Parent: "presentations/submissions",
				Filter: "done = false",
			}
			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/operations", value)
			w := httptest.NewRecorder()

			assert.NoError(t, opRouter.GetOperations(newRequestContext(), w, req))

			var resp router.GetOperationsResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Len(t, resp.Operations, 1)
			assert.False(t, resp.Operations[0].Done)
		})

		t.Run("Returns zero operations when filtering to exclude", func(tt *testing.T) {
			s := setupTestDB(tt)
			pRouter := setupPresentationRouter(t, s)
			opRouter := setupOperationsRouter(t, s)

			def := createPresentationDefinition(t, pRouter)
			holderSigner, holderDID := getSigner(t)
			_ = createSubmission(t, pRouter, def.PresentationDefinition.ID, VerifiableCredential(), holderDID, holderSigner)

			request := router.GetOperationsRequest{
				Parent: "presentations/submissions",
				Filter: "done = true",
			}
			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/operations", value)
			w := httptest.NewRecorder()

			assert.NoError(t, opRouter.GetOperations(newRequestContext(), w, req))

			var resp router.GetOperationsResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Empty(t, resp.Operations)
		})

		t.Run("Returns zero operations when wrong parent is specified", func(tt *testing.T) {
			s := setupTestDB(tt)
			pRouter := setupPresentationRouter(t, s)
			opRouter := setupOperationsRouter(t, s)

			def := createPresentationDefinition(t, pRouter)
			holderSigner, holderDID := getSigner(t)
			_ = createSubmission(t, pRouter, def.PresentationDefinition.ID, VerifiableCredential(), holderDID, holderSigner)

			request := router.GetOperationsRequest{
				Parent: "/presentations/other",
			}
			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/operations", value)
			w := httptest.NewRecorder()

			assert.NoError(t, opRouter.GetOperations(newRequestContext(), w, req))

			var resp router.GetOperationsResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Empty(t, resp.Operations)
		})
	})

	t.Run("CancelOperation", func(t *testing.T) {
		t.Run("Marks an operation as done", func(t *testing.T) {
			s := setupTestDB(t)
			pRouter := setupPresentationRouter(t, s)
			opRouter := setupOperationsRouter(t, s)

			holderSigner, holderDID := getSigner(t)
			definition := createPresentationDefinition(t, pRouter)
			submissionOp := createSubmission(t, pRouter, definition.PresentationDefinition.ID, VerifiableCredential(), holderDID, holderSigner)

			createdID := submissionOp.ID
			req := httptest.NewRequest(
				http.MethodPut,
				fmt.Sprintf("https://ssi-service.com/v1/operations/%s", createdID),
				nil)
			w := httptest.NewRecorder()

			err := opRouter.CancelOperation(newRequestContextWithParams(map[string]string{"id": createdID}), w, req)

			assert.NoError(t, err)
			var resp router.Operation
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.True(t, resp.Done)
			assert.Contains(t, resp.Result.Response, "definition_id")
			assert.Contains(t, resp.Result.Response, "descriptor_map")
			assert.Equal(t, "cancelled", resp.Result.Response.(map[string]any)["status"])
		})

		t.Run("Returns error when operation is done already", func(t *testing.T) {
			s := setupTestDB(t)
			pRouter := setupPresentationRouter(t, s)
			opRouter := setupOperationsRouter(t, s)

			holderSigner, holderDID := getSigner(t)
			definition := createPresentationDefinition(t, pRouter)
			submissionOp := createSubmission(t, pRouter, definition.PresentationDefinition.ID, VerifiableCredential(), holderDID, holderSigner)
			_ = reviewSubmission(t, pRouter, submission.ID(submissionOp.ID))

			createdID := submissionOp.ID
			req := httptest.NewRequest(
				http.MethodPut,
				fmt.Sprintf("https://ssi-service.com/v1/operations/%s", createdID),
				nil)
			w := httptest.NewRecorder()

			err := opRouter.CancelOperation(newRequestContextWithParams(map[string]string{"id": createdID}), w, req)

			assert.Error(t, err)
		})
	})

}

func createCredential(tt *testing.T, credRouter *router.CredentialRouter, issuerDID, subjectDID, schemaID string, data map[string]any) router.CreateCredentialResponse {
	request := router.CreateCredentialRequest{
		Issuer:  issuerDID,
		Subject: subjectDID,
		Schema:  schemaID,
		Data:    data,
	}

	value := newRequestValue(tt, request)
	req := httptest.NewRequest(
		http.MethodPut,
		"https://ssi-service.com/v1/credentials",
		value)
	w := httptest.NewRecorder()

	err := credRouter.CreateCredential(newRequestContext(), w, req)

	assert.NoError(tt, err)

	var resp router.CreateCredentialResponse
	assert.NoError(tt, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

func submitApplication(tt *testing.T, mRouter *router.ManifestRouter, manifest router.CreateManifestResponse, credJWT *keyaccess.JWT, applicantDID router.CreateDIDByMethodResponse) router.Operation {
	m := manifest.Manifest

	container := []credmodel.Container{{CredentialJWT: credJWT}}

	applicationRequest := getValidApplicationRequest(m.ID, m.PresentationDefinition.ID, m.PresentationDefinition.InputDescriptors[0].ID, container)

	applicantPrivKeyBytes, err := base58.Decode(applicantDID.PrivateKeyBase58)
	assert.NoError(tt, err)
	applicantPrivKey, err := crypto.BytesToPrivKey(applicantPrivKeyBytes, applicantDID.KeyType)
	assert.NoError(tt, err)
	signer, err := keyaccess.NewJWKKeyAccess(applicantDID.DID.ID, applicantPrivKey)
	assert.NoError(tt, err)
	signed, err := signer.SignJSON(applicationRequest)
	assert.NoError(tt, err)

	request := router.SubmitApplicationRequest{
		ApplicationJWT: *signed,
	}

	value := newRequestValue(tt, request)
	req := httptest.NewRequest(
		http.MethodPut,
		"https://ssi-service.com/v1/dids/key",
		value)
	w := httptest.NewRecorder()

	err = mRouter.SubmitApplication(newRequestContext(), w, req)

	assert.NoError(tt, err)

	var resp router.Operation
	assert.NoError(tt, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

func createSchema(tt *testing.T, schemaRouter *router.SchemaRouter, author string) router.CreateSchemaResponse {
	licenseSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"licenseType": map[string]any{
				"type": "string",
			},
		},
		"additionalProperties": true,
	}
	request := router.CreateSchemaRequest{Author: author, Name: "license schema", Schema: licenseSchema, Sign: true}
	value := newRequestValue(tt, request)
	req := httptest.NewRequest(
		http.MethodPut,
		"https://ssi-service.com/v1/schemas",
		value)
	w := httptest.NewRecorder()

	err := schemaRouter.CreateSchema(newRequestContext(), w, req)

	assert.NoError(tt, err)

	var resp router.CreateSchemaResponse
	assert.NoError(tt, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

func createDID(tt *testing.T, didRouter *router.DIDRouter) router.CreateDIDByMethodResponse {
	request := router.CreateDIDByMethodRequest{
		KeyType: crypto.Ed25519,
	}
	value := newRequestValue(tt, request)
	req := httptest.NewRequest(
		http.MethodPut,
		"https://ssi-service.com/v1/dids/key",
		value)
	w := httptest.NewRecorder()

	err := didRouter.CreateDIDByMethod(newRequestContextWithParams(map[string]string{"method": "key"}), w, req)

	assert.NoError(tt, err)

	var resp router.CreateDIDByMethodResponse
	assert.NoError(tt, json.NewDecoder(w.Body).Decode(&resp))
	return resp

}
func createManifest(tt *testing.T, manifestRouter *router.ManifestRouter, issuerDID, schemaID string) router.CreateManifestResponse {
	createManifestRequest := getValidManifestRequest(issuerDID, schemaID)

	requestValue := newRequestValue(tt, createManifestRequest)
	req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
	w := httptest.NewRecorder()
	err := manifestRouter.CreateManifest(newRequestContext(), w, req)
	assert.NoError(tt, err)

	var resp router.CreateManifestResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(tt, err)

	return resp
}

func setupTestDB(t *testing.T) storage.ServiceStorage {
	file, err := os.CreateTemp("", "bolt")
	require.NoError(t, err)
	name := file.Name()
	s, err := storage.NewStorage(storage.Bolt, name)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = s.Close()
		_ = file.Close()
		_ = os.Remove(name)
	})
	return s
}

func reviewSubmission(t *testing.T, pRouter *router.PresentationRouter, submissionID string) router.ReviewSubmissionResponse {
	request := router.ReviewSubmissionRequest{
		Approved: true,
		Reason:   "because I want to",
	}

	value := newRequestValue(t, request)
	req := httptest.NewRequest(
		http.MethodPut,
		fmt.Sprintf("https://ssi-service.com/v1/presentations/submissions/%s/review", submissionID),
		value)
	w := httptest.NewRecorder()

	err := pRouter.ReviewSubmission(newRequestContextWithParams(map[string]string{"id": submissionID}), w, req)

	assert.NoError(t, err)
	var resp router.ReviewSubmissionResponse
	assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

func setupOperationsRouter(t *testing.T, s storage.ServiceStorage) *router.OperationRouter {
	svc, err := operation.NewOperationService(s)
	assert.NoError(t, err)
	opRouter, err := router.NewOperationRouter(svc)
	assert.NoError(t, err)
	return opRouter
}
