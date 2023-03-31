package authorizationserver

import (
	"context"
	"net/http"

	"github.com/sirupsen/logrus"
)

// IntrospectionEndpoint is a handler that implements https://www.rfc-editor.org/rfc/rfc7662
func (s AuthService) IntrospectionEndpoint(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
	mySessionData := newSession("")
	ir, err := s.provider.NewIntrospectionRequest(ctx, req, mySessionData)
	if err != nil {
		logrus.WithError(err).Error("failed NewIntrospectionRequest")
		s.provider.WriteIntrospectionError(ctx, rw, err)
		return nil
	}

	s.provider.WriteIntrospectionResponse(ctx, rw, ir)
	return nil
}
