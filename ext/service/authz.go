package service

import (
	"context"
	securityProto "github.com/nocturna-ta/api-gateway-grpc-lib/proto"
	"github.com/nocturna-ta/golib/grpc"
)

type auth struct {
	authSvc securityProto.AuthServiceClient
}

type Auth interface {
	Validate(ctx context.Context, req *AuthValidateRequest) (*AuthValidateResponse, error)
}

func NewAuthSvc(address string) Auth {
	c := grpc.NewClient(&grpc.ClientOptions{
		Address: address,
	})

	authSvc := securityProto.NewAuthServiceClient(c.GetConn())

	return &auth{
		authSvc: authSvc,
	}
}

func (a *auth) Validate(ctx context.Context, req *AuthValidateRequest) (*AuthValidateResponse, error) {
	res, err := a.authSvc.ValidateAuthorization(ctx, &securityProto.AuthValidateRequest{
		Headers:       req.Header,
		Path:          req.Path,
		TargetService: req.TargetService,
	})
	if err != nil {
		return nil, err
	}

	return &AuthValidateResponse{
		IsValid:       res.IsValid,
		InjectHeaders: res.ExplodeHeader,
	}, nil
}
