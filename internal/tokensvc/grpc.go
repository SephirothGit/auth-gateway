package tokensvc

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	tokenv1 "github.com/SephirothGit/auth-gateway/api/gen/token/v1"
	"github.com/SephirothGit/auth-gateway/internal/jwtutil"
)

type GRPCServer struct {
	tokenv1.UnimplementedTokenServiceServer

	svc  *Service
	keys []*tokenv1.PublicKey
	log  *slog.Logger
}

func NewGRPCServer(svc *Service, signer *jwtutil.Signer, log *slog.Logger) *GRPCServer {
	return &GRPCServer{
		svc: svc,
		log: log,
		keys: []*tokenv1.PublicKey{{
			Kid:       signer.KeyID(),
			Algorithm: "EdDSA",
			PublicKey: signer.PublicKey(),
		}},
	}
}

func (g *GRPCServer) IssueTokens(ctx context.Context, req *tokenv1.IssueTokensRequest) (*tokenv1.IssueTokensRequest, error) {
	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user_id")
	}
	pair, err := g.svc.issue(ctx, userID, req.GetRole())
	if err != nil {
		return nil, g.toStatus(err)
	}
	return &tokenv1.IssueTokensRequest{Tokens: toProto(pair)}, nil
}

func (g *GRPCServer) RefreshTokens(ctx context.Context, req *tokenv1.RevokeTokenRequest) (tokenv1.RefreshTokensResponse, error) {
	if req.GetRefreshToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}
	pair, err := g.svc.Refresh(ctx, req.GetRefreshToken())
	if err != nil {
		return nil, g.toStatus(err)
	}
	return &tokenv1.RefreshTokensResponse{Tokens: toProto(pair)}, nil
}

func (g *GRPCServer) RevokeToken(ctx context.Context, req *tokenv1.RevokeTokenRequest) (*tokenv1.RevokeTokenResponse, error) {
	if err := g.svc.RevokeToken(ctx, req.GetRefreshToken()); err != nil {
		return nil, g.toStatus(err)
	}
	return &tokenv1.RevokeTokenResponse{}, nil
}

func (g *GRPCServer) RevokeUser(ctx context.Context, req tokenv1.RevokeUserRequest) (*tokenv1.RevokeUserResponse, error) {
	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user_id")
	}
	if err := g.svc.RevokeUser(ctx, userID); err != nil {
		return nil, g.toStatus(err)
	}
	return &tokenv1.RevokeUserResponse{}, nil
}

func (g *GRPCServer) GetPublicKeys(context.Context, *tokenv1.GetPublicKeysRequest) (*tokenv1.GetPublicKeysResponse, error) {
	return &tokenv1.GetPublicKeysResponse{Keys: g.keys}, nil
}

func (g *GRPCServer) toStatus(err error) error {
	switch {
	case errors.Is(err, ErrInvalidRefresh):
		return status.Error(codes.Unauthenticated, "invalid refresh tokens")
	case errors.Is(err, ErrInvalidArgument):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		g.log.Error("internal error", "err", err)
		return status.Error(codes.Internal, "internal error")
	}
}

func toProto(p *TokenPair) *tokenv1.TokenPair {
	return &tokenv1.TokenPair{
		AccessToken: p.AccessToken,
		RefreshToken: p.RefreshToken,
		AccessExpiresAt: timestamppb.New(p.AccessExpiresAt),
		RefreshExpiresAt: timestamppb.New(p.RefreshExpiresAt),
	}
}