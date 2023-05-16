package router

import (
	"context"
	"fmt"
	"net/http"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"go.einride.tech/aip/filtering"

	credint "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation/model"
)

type PresentationRouter struct {
	service *presentation.Service
}

func NewPresentationRouter(s svcframework.Service) (*PresentationRouter, error) {
	if s == nil {
		return nil, errors.New("service cannot be nil")
	}
	service, ok := s.(*presentation.Service)
	if !ok {
		return nil, fmt.Errorf("could not create presentation router with service type: %s", s.Type())
	}
	return &PresentationRouter{service: service}, nil
}

type CreatePresentationRequestRequest struct {
	Name                   string                           `json:"name,omitempty"`
	Purpose                string                           `json:"purpose,omitempty"`
	Format                 *exchange.ClaimFormat            `json:"format,omitempty" validate:"omitempty,dive"`
	InputDescriptors       []exchange.InputDescriptor       `json:"inputDescriptors" validate:"required,dive"`
	SubmissionRequirements []exchange.SubmissionRequirement `json:"submissionRequirements,omitempty" validate:"omitempty,dive"`

	// DID of the author of this presentation request. The DID must have been previously created with the DID API,
	// or the PrivateKey must have been added independently.
	Author string `json:"author" validate:"required"`
	// The privateKey associated with the KID will be used to sign the presentation request.
	AuthorKID string `json:"authorKid" validate:"required"`
}

type CreatePresentationRequestResponse struct {
	PresentationRequest exchange.PresentationDefinitionEnvelope `json:"presentation_request"`

	// Signed request that contains the PresentationRequest created using the privateKey of the author of the
	// definition.
	PresentationRequestJWT keyaccess.JWT `json:"presentationRequestJWT"`
}

// CreatePresentationRequest godoc
//
// @Summary     Create PresentationRequest
// @Description Creates a presentation request object as described in https://identity.foundation/presentation-exchange/#presentation-request.
// @Description We define this object as an envelope which contains a single json field `presentation_definition`.
// @Tags        PresentationRequestAPI
// @Accept      json
// @Produce     json
// @Param       request body     CreatePresentationRequestRequest true "request body"
// @Success     201     {object} CreatePresentationRequestResponse
// @Failure     400     {string} string "Bad request"
// @Failure     500     {string} string "Internal server error"
// @Router      /v1/presentation/requests [put]
func (pr PresentationRouter) CreatePresentationRequest(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var request CreatePresentationRequestRequest
	errMsg := "Invalid Presentation Definition Request"
	if err := framework.Decode(r, &request); err != nil {
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	if err := framework.ValidateRequest(request); err != nil {
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	def, err := definitionFromRequest(request)
	if err != nil {
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}
	serviceResp, err := pr.service.CreatePresentationRequest(ctx, model.CreatePresentationRequestRequest{
		PresentationDefinition: *def,
		Author:                 request.Author,
		AuthorKID:              request.AuthorKID,
	})
	if err != nil {
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	resp := CreatePresentationRequestResponse{
		PresentationRequest:    serviceResp.PresentationRequest,
		PresentationRequestJWT: serviceResp.PresentationRequestJWT,
	}
	return framework.Respond(ctx, w, resp, http.StatusCreated)
}

func definitionFromRequest(request CreatePresentationRequestRequest) (*exchange.PresentationDefinition, error) {
	b := exchange.NewPresentationDefinitionBuilder()
	if err := b.SetName(request.Name); err != nil {
		return nil, err
	}
	if err := b.SetPurpose(request.Purpose); err != nil {
		return nil, err
	}
	if request.Format != nil {
		if err := b.SetClaimFormat(*request.Format); err != nil {
			return nil, err
		}
	}
	if len(request.SubmissionRequirements) > 0 {
		if err := b.SetSubmissionRequirements(request.SubmissionRequirements); err != nil {
			return nil, err
		}
	}
	if len(request.InputDescriptors) > 0 {
		if err := b.SetInputDescriptors(request.InputDescriptors); err != nil {
			return nil, err
		}
	}

	req, err := b.Build()
	if err != nil {
		return nil, err
	}
	return req, nil
}

type GetPresentationRequestResponse struct {
	PresentationRequest exchange.PresentationDefinitionEnvelope `json:"presentationRequest"`

	// Signed envelope that contains the PresentationDefinition created using the privateKey of the author of the
	// definition.
	PresentationRequestJWT keyaccess.JWT `json:"presentationRequestJWT"`
}

// GetPresentationRequest godoc
//
// @Summary     Get PresentationRequest
// @Description Get a presentation request by its ID
// @Tags        PresentationRequestAPI
// @Accept      json
// @Produce     json
// @Param       id  path     string true "ID"
// @Success     200 {object} GetPresentationRequestResponse
// @Failure     400 {string} string "Bad request"
// @Router      /v1/presentation/requests/{id} [get]
func (pr PresentationRouter) GetPresentationRequest(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot get presentation without ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	def, err := pr.service.GetPresentationRequest(ctx, model.GetPresentationRequestRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get presentation with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	resp := GetPresentationRequestResponse{
		PresentationRequest:    def.PresentationRequest,
		PresentationRequestJWT: def.PresentationRequestJWT,
	}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

type ListPresentationRequestsRequest struct {
}

type ListPresentationRequestsResponse struct {
	PresentationRequests []*exchange.PresentationDefinitionEnvelope `json:"requests"`
}

// ListPresentationRequests godoc
//
// @Summary     List Presentation Requests
// @Description Lists all the existing presentation requests
// @Tags        PresentationDefinitionAPI
// @Accept      json
// @Produce     json
// @Param       request body     ListPresentationRequestsRequest true "request body"
// @Success     200     {object} ListPresentationRequestsResponse
// @Failure     400     {string} string "Bad request"
// @Failure     500     {string} string "Internal server error"
// @Router      /v1/presentations/requests [get]
func (pr PresentationRouter) ListPresentationRequests(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	svcResponse, err := pr.service.ListPresentationRequests(ctx)
	if err != nil {
		errMsg := "could not get definitions"
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	resp := ListPresentationRequestsResponse{
		PresentationRequests: svcResponse.Requests,
	}

	return framework.Respond(ctx, w, resp, http.StatusOK)
}

// DeletePresentationRequest godoc
//
// @Summary     Delete PresentationRequest
// @Description Delete a presentation definition by its ID
// @Tags        PresentationDefinitionAPI
// @Accept      json
// @Produce     json
// @Param       id  path     string true "ID"
// @Success     204 {string} string "No Content"
// @Failure     400 {string} string "Bad request"
// @Failure     500 {string} string "Internal server error"
// @Router      /v1/presentation/requests/{id} [delete]
func (pr PresentationRouter) DeletePresentationRequest(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot delete a presentation without an ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	if err := pr.service.DeletePresentationRequest(ctx, model.DeletePresentationRequestRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete presentation with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	return framework.Respond(ctx, w, nil, http.StatusNoContent)
}

type CreateSubmissionRequest struct {
	SubmissionJWT keyaccess.JWT `json:"submissionJwt" validate:"required"`
}

func (r CreateSubmissionRequest) toServiceRequest() (*model.CreateSubmissionRequest, error) {
	_, _, vp, err := credential.ParseVerifiablePresentationFromJWT(r.SubmissionJWT.String())
	if err != nil {
		return nil, errors.Wrap(err, "parsing presentation from jwt")
	}
	if err := vp.IsValid(); err != nil {
		return nil, errors.Wrap(err, "verifying vp validity")
	}

	submissionData, err := json.Marshal(vp.PresentationSubmission)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling presentation_submission")
	}
	var s exchange.PresentationSubmission
	if err := json.Unmarshal(submissionData, &s); err != nil {
		return nil, errors.Wrap(err, "unmarshalling presentation submission")
	}
	if err := s.IsValid(); err != nil {
		return nil, errors.Wrap(err, "verifying submission validity")
	}
	vp.PresentationSubmission = s

	credContainers, err := credint.NewCredentialContainerFromArray(vp.VerifiableCredential)
	if err != nil {
		return nil, errors.Wrap(err, "parsing verifiable credential array")
	}

	return &model.CreateSubmissionRequest{
		Presentation:  *vp,
		SubmissionJWT: r.SubmissionJWT,
		Submission:    s,
		Credentials:   credContainers}, nil
}

// CreateSubmission godoc
//
// @Summary     Create Submission
// @Description Creates a submission in this server ready to be reviewed.
// @Tags        PresentationSubmissionAPI
// @Accept      json
// @Produce     json
// @Param       request body     CreateSubmissionRequest true "request body"
// @Success     201     {object} Operation               "The type of response is Submission once the operation has finished."
// @Failure     400     {string} string                  "Bad request"
// @Failure     500     {string} string                  "Internal server error"
// @Router      /v1/presentations/submissions [put]
func (pr PresentationRouter) CreateSubmission(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var request CreateSubmissionRequest
	if err := framework.Decode(r, &request); err != nil {
		return framework.NewRequestError(
			sdkutil.LoggingErrorMsg(err, "invalid create submission request"), http.StatusBadRequest)
	}

	req, err := request.toServiceRequest()
	if err != nil {
		return framework.NewRequestError(
			sdkutil.LoggingErrorMsg(err, "invalid create submission request"), http.StatusBadRequest)
	}

	operation, err := pr.service.CreateSubmission(ctx, *req)
	if err != nil {
		return framework.NewRequestError(
			sdkutil.LoggingErrorMsg(err, "cannot create submission"), http.StatusInternalServerError)
	}

	resp := Operation{ID: operation.ID}
	return framework.Respond(ctx, w, resp, http.StatusCreated)
}

type GetSubmissionResponse struct {
	*model.Submission
	// TODO(OSE-334): Actually add the credentials that were sent.
}

// GetSubmission godoc
//
// @Summary     Get Submission
// @Description Get a submission by its ID
// @Tags        PresentationSubmissionAPI
// @Accept      json
// @Produce     json
// @Param       id  path     string true "ID"
// @Success     200 {object} GetSubmissionResponse
// @Failure     400 {string} string "Bad request"
// @Router      /v1/presentations/submissions/{id} [get]
func (pr PresentationRouter) GetSubmission(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		return framework.NewRequestError(
			sdkutil.LoggingNewError("get submission request requires id"), http.StatusBadRequest)
	}

	submission, err := pr.service.GetSubmission(ctx, model.GetSubmissionRequest{ID: *id})

	if err != nil {
		return framework.NewRequestError(
			sdkutil.LoggingErrorMsg(err, "failed getting submission"), http.StatusBadRequest)
	}
	resp := GetSubmissionResponse{
		Submission: &submission.Submission,
	}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

type ListSubmissionRequest struct {
	// A standard filter expression conforming to https://google.aip.dev/160.
	// For example: `status = "done"`.
	Filter string `json:"filter"`
}

func (l ListSubmissionRequest) GetFilter() string {
	return l.Filter
}

type ListSubmissionResponse struct {
	Submissions []model.Submission `json:"submissions"`
}

// ListSubmissions godoc
//
// @Summary     List Submissions
// @Description List existing submissions according to a filtering query. The `filter` field follows the syntax described in https://google.aip.dev/160.
// @Tags        PresentationSubmissionAPI
// @Accept      json
// @Produce     json
// @Param       request body     ListSubmissionRequest true "request body"
// @Success     200     {object} ListSubmissionResponse
// @Failure     400     {string} string "Bad request"
// @Failure     500     {string} string "Internal server error"
// @Router      /v1/presentations/submissions [get]
func (pr PresentationRouter) ListSubmissions(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var request ListSubmissionRequest
	if err := framework.Decode(r, &request); err != nil {
		return framework.NewRequestError(
			sdkutil.LoggingErrorMsg(err, "invalid list submissions request"), http.StatusBadRequest)
	}

	const StatusIdentifier = "status"
	declarations, err := filtering.NewDeclarations(
		filtering.DeclareFunction(filtering.FunctionEquals,
			filtering.NewFunctionOverload(
				filtering.FunctionOverloadEqualsString, filtering.TypeBool, filtering.TypeString, filtering.TypeString)),
		filtering.DeclareIdent(StatusIdentifier, filtering.TypeString),
	)
	if err != nil {
		return framework.NewRequestError(
			sdkutil.LoggingErrorMsg(err, "creating filter declarations"), http.StatusInternalServerError)
	}

	// Because parsing filters can be expensive, we limit is to a fixed len of chars. That should be more than enough
	// for most use cases.
	if len(request.GetFilter()) > FilterCharacterLimit {
		err := errors.Errorf("filter longer than %d character size limit", FilterCharacterLimit)
		return framework.NewRequestError(
			sdkutil.LoggingErrorMsg(err, "invalid filter"), http.StatusBadRequest)

	}
	filter, err := filtering.ParseFilter(request, declarations)
	if err != nil {
		return framework.NewRequestError(
			sdkutil.LoggingErrorMsg(err, "invalid filter"), http.StatusBadRequest)
	}
	resp, err := pr.service.ListSubmissions(ctx, model.ListSubmissionRequest{Filter: filter})
	if err != nil {
		return framework.NewRequestError(
			sdkutil.LoggingErrorMsg(err, "failed listing submissions"), http.StatusInternalServerError)
	}
	return framework.Respond(ctx, w, ListSubmissionResponse{Submissions: resp.Submissions}, http.StatusOK)
}

type ReviewSubmissionRequest struct {
	Approved bool   `json:"approved" validate:"required"`
	Reason   string `json:"reason"`
}

func (r ReviewSubmissionRequest) toServiceRequest(id string) model.ReviewSubmissionRequest {
	return model.ReviewSubmissionRequest{
		ID:       id,
		Approved: r.Approved,
		Reason:   r.Reason,
	}
}

type ReviewSubmissionResponse struct {
	*model.Submission
}

// ReviewSubmission godoc
//
// @Summary     Review a pending submission
// @Description Reviews a pending submission. After this method is called, the operation with `id==presentations/submissions/{submission_id}` will be updated with the result of this invocation.
// @Tags        PresentationSubmissionAPI
// @Accept      json
// @Produce     json
// @Param       request body     ReviewSubmissionRequest true "request body"
// @Success     200     {object} ReviewSubmissionResponse
// @Failure     400     {string} string "Bad request"
// @Failure     500     {string} string "Internal server error"
// @Router      /v1/presentations/submissions/{id}/review [put]
func (pr PresentationRouter) ReviewSubmission(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		return framework.NewRequestError(
			sdkutil.LoggingNewError("review submission request requires id"), http.StatusBadRequest)
	}

	var request ReviewSubmissionRequest
	if err := framework.Decode(r, &request); err != nil {
		return framework.NewRequestError(
			sdkutil.LoggingErrorMsg(err, "invalid review submissions request"), http.StatusBadRequest)
	}

	req := request.toServiceRequest(*id)
	submission, err := pr.service.ReviewSubmission(ctx, req)
	if err != nil {
		return framework.NewRequestError(
			sdkutil.LoggingErrorMsg(err, "failed reviewing submission"), http.StatusInternalServerError)
	}
	return framework.Respond(ctx, w, ReviewSubmissionResponse{Submission: submission}, http.StatusOK)
}
