package proxyhandler

import (
	"context"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/Vilinvil/hw-security-1/pkg/httputils"
)

type Config struct {
	ModeTLS      bool
	BasicTimeout time.Duration
}

type ProxyHandler struct {
	client *http.Client
}

func NewProxyHandler(_ context.Context, config *Config) (*ProxyHandler, error) {
	client := &http.Client{Timeout: config.BasicTimeout} //nolint:exhaustruct

	client.Transport = http.DefaultTransport

	return &ProxyHandler{client: client}, nil
}

func (p *ProxyHandler) Proxy(w http.ResponseWriter, r *http.Request) {
	log.Println(r)
	log.Println("______________________")

	err := httputils.SetForwardedHeader(r)
	if err != nil {
		return
	}

	r.Header.Del(httputils.HeaderProxyConnection)

	log.Println(r)

	log.Println("______________________")

	r.RequestURI = ""

	resp, err := p.client.Do(r)
	if err != nil {
		log.Println(err)

		return
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		httputils.WriteErrorHTTP(w, http.StatusInternalServerError, httputils.InternalErrorMessage)

		return
	}

	err = resp.Body.Close()
	if err != nil {
		log.Println(err)
	}

	httputils.WriteOkHTTP(w, httputils.ConvertResponseToString(resp))
	httputils.WriteSlByte(w, respBody)
}
