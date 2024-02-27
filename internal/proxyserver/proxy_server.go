package proxyserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"github.com/Vilinvil/hw-security-1/internal/config"
	"github.com/Vilinvil/hw-security-1/internal/proxyserver/delivery/mux"
	"github.com/Vilinvil/hw-security-1/internal/proxyserver/delivery/proxyhandler"
	"github.com/Vilinvil/hw-security-1/pkg/myerrors"
)

const CoefficientReadServerTimeout = 30

type ProxyServer struct {
	server *http.Server
}

func (p *ProxyServer) Run(config *config.Config) error {
	baseCtx := context.Background()

	handler, err := mux.NewMux(baseCtx, &proxyhandler.Config{
		ModeTLS:      config.ModeTLS,
		BasicTimeout: config.BasicTimeout,
	})
	if err != nil {
		return fmt.Errorf(myerrors.ErrTemplate, err)
	}

	p.server = &http.Server{ //nolint:exhaustruct
		Addr:           ":" + config.PortServer,
		Handler:        handler,
		MaxHeaderBytes: http.DefaultMaxHeaderBytes,
		ReadTimeout:    CoefficientReadServerTimeout * config.BasicTimeout,
		WriteTimeout:   config.BasicTimeout,
		TLSConfig:      &tls.Config{ServerName: config.HostServer},
	}

	log.Printf("Start server:%s\n", config.PortServer)

	if config.ModeTLS {
		return p.server.ListenAndServeTLS(config.CertFileTLS, config.KeyFileTLS) //nolint:wrapcheck
	}

	return p.server.ListenAndServe() //nolint:wrapcheck
}
