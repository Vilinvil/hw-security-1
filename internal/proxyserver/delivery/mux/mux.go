package mux

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Vilinvil/hw-security-1/internal/proxyserver/delivery/proxyhandler"
	"github.com/Vilinvil/hw-security-1/pkg/myerrors"
)

func NewMux(ctx context.Context, config *proxyhandler.Config) (http.Handler, error) {
	proxyHandler, err := proxyhandler.NewProxyHandler(ctx, config)
	if err != nil {
		return nil, fmt.Errorf(myerrors.ErrTemplate, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", proxyHandler.Proxy)

	return mux, nil
}
