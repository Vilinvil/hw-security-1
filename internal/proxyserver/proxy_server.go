package proxyserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"github.com/Vilinvil/hw-security-1/internal/config"
	"github.com/Vilinvil/hw-security-1/internal/proxyserver/delivery/proxyhandler"
	"github.com/Vilinvil/hw-security-1/pkg/myerrors"
)

const CoefficientReadServerTimeout = 30

type ProxyServer struct {
	server *http.Server
}

func (p *ProxyServer) Run(config *config.Config) error {
	baseCtx := context.Background()

	tlsServerConfig := &tls.Config{ //nolint:exhaustruct
		ServerName: config.HostServer,
		MinVersion: tls.VersionTLS12,
	}

	proxyHandler, err := proxyhandler.NewProxyHandler(baseCtx, &proxyhandler.Config{
		ModeTLS:         config.ModeTLS,
		CertFileTLS:     config.CertFileTLS,
		KeyFileTLS:      config.KeyFileTLS,
		TLSServerConfig: tlsServerConfig,
		BasicTimeout:    config.BasicTimeout,
	})
	if err != nil {
		return fmt.Errorf(myerrors.ErrTemplate, err)
	}

	p.server = &http.Server{ //nolint:exhaustruct
		Addr:           ":" + config.PortServer,
		Handler:        proxyHandler,
		MaxHeaderBytes: http.DefaultMaxHeaderBytes,
		ReadTimeout:    CoefficientReadServerTimeout * config.BasicTimeout,
		WriteTimeout:   config.BasicTimeout,
		TLSConfig:      tlsServerConfig,
	}

	log.Printf("Start server:%s\n", config.PortServer)

	if config.ModeTLS {
		return p.server.ListenAndServeTLS(config.CertFileTLS, config.KeyFileTLS) //nolint:wrapcheck
	}

	return p.server.ListenAndServe() //nolint:wrapcheck
}
