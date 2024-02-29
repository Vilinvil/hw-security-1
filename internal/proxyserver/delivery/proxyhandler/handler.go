package proxyhandler

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/Vilinvil/hw-security-1/pkg/cert"
	"github.com/Vilinvil/hw-security-1/pkg/deliveryutil"
	"github.com/Vilinvil/hw-security-1/pkg/myerrors"
)

const IncorrectHostMessage = "получили не корректный хост"

type Config struct {
	ModeTLS         bool
	CertFileTLS     string
	KeyFileTLS      string
	TLSServerConfig *tls.Config
	BasicTimeout    time.Duration
}

type ProxyHandler struct {
	client          *http.Client
	certCA          *tls.Certificate
	tlsServerConfig *tls.Config
	basicTimeout    time.Duration
}

func NewProxyHandler(_ context.Context, config *Config) (*ProxyHandler, error) {
	client := &http.Client{Timeout: config.BasicTimeout} //nolint:exhaustruct

	client.Transport = http.DefaultTransport

	proxyHandler := &ProxyHandler{ //nolint:exhaustruct
		client:          client,
		tlsServerConfig: config.TLSServerConfig,
		basicTimeout:    config.BasicTimeout,
	}

	err := proxyHandler.initCertCA(config.CertFileTLS, config.KeyFileTLS)
	if err != nil {
		return nil, fmt.Errorf(myerrors.ErrTemplate, err)
	}

	return proxyHandler, nil
}

func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleTunneling(w, r)

		return
	}

	err := deliveryutil.SetForwardedHeader(r)
	if err != nil {
		return
	}

	deliveryutil.RemoveHopByHopHeaders(r.Header)

	log.Println(r)
	log.Println("______________________")

	r.RequestURI = ""

	resp, err := p.client.Do(r)
	if err != nil {
		log.Println(err)
		http.Error(w, deliveryutil.InternalErrorMessage, http.StatusInternalServerError)

		return
	}

	deliveryutil.RemoveHopByHopHeaders(resp.Header)
	deliveryutil.WriteOkHTTP(w, deliveryutil.ConvertResponseToString(resp))

	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Println(err)
		http.Error(w, deliveryutil.InternalErrorMessage, http.StatusInternalServerError)

		return
	}

	err = resp.Body.Close()
	if err != nil {
		log.Println(err)

		return
	}
}

func (p *ProxyHandler) initCertCA(certFile, keyFile string) error {
	certRaw, err := os.ReadFile(certFile)
	if err != nil {
		log.Println(err)

		return fmt.Errorf(myerrors.ErrTemplate, err)
	}

	keyRaw, err := os.ReadFile(keyFile)
	if err != nil {
		log.Println(err)

		return fmt.Errorf(myerrors.ErrTemplate, err)
	}

	certX509, err := tls.X509KeyPair(certRaw, keyRaw)
	if err != nil {
		log.Println(err)

		return fmt.Errorf(myerrors.ErrTemplate, err)
	}

	certX509.Leaf, err = x509.ParseCertificate(certX509.Certificate[0])
	if err != nil {
		log.Println(err)

		return fmt.Errorf(myerrors.ErrTemplate, err)
	}

	p.certCA = &certX509

	return nil
}

func (p *ProxyHandler) handleTunneling(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		log.Println(err)
		http.Error(w, IncorrectHostMessage, http.StatusBadRequest)
	}

	hostCert, err := cert.GenCert(p.certCA, []string{host})
	if err != nil {
		log.Println(err)
		http.Error(w, deliveryutil.InternalErrorMessage, http.StatusInternalServerError)

		return
	}

	p.tlsServerConfig.Certificates = append(p.tlsServerConfig.Certificates, *hostCert)

	clientConn, err := handshake(w, p.tlsServerConfig)
	if err != nil {
		return
	}

	serverConn, err := net.DialTimeout("tcp", r.Host, p.basicTimeout)
	if err != nil {
		log.Println(err)
		http.Error(w, httputils.InternalErrorMessage, http.StatusInternalServerError)

		return
	}

	chDoneWrite := make(chan struct{})
	go func() {
		_, err := io.Copy(serverConn, clientConn)
		if err != nil {
			log.Println(err)
		}
		chDoneWrite <- struct{}{}
	}()
	go func() {
		<-chDoneWrite

		_, err := io.Copy(clientConn, serverConn)
		if err != nil {
			log.Println(err)
		}

		errClose := clientConn.Close()
		if errClose != nil {
			log.Println(errClose)
		}

		errClose = serverConn.Close()
		if errClose != nil {
			log.Println(errClose)
		}
	}()
}

var ErrHijacker = myerrors.NewError("error type assert Hijacker")

const okHeader = "HTTP/1.1 200 OK\r\n\r\n"

// handshake hijacks w's underlying net.Conn, responds to the CONNECT request
// and manually performs the TLS handshake.
func handshake(w http.ResponseWriter, config *tls.Config) (net.Conn, error) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Println(ErrHijacker)

		return nil, fmt.Errorf(myerrors.ErrTemplate, ErrHijacker)
	}

	raw, _, err := hijacker.Hijack()
	if err != nil {
		log.Println(err)
		http.Error(w, deliveryutil.InternalErrorMessage, http.StatusInternalServerError)

		return nil, fmt.Errorf(myerrors.ErrTemplate, err)
	}

	if _, err = raw.Write([]byte(okHeader)); err != nil {
		log.Println(err)

		errClose := raw.Close()
		if err != nil {
			log.Println(errClose)
		}

		return nil, fmt.Errorf(myerrors.ErrTemplate, err)
	}

	conn := tls.Server(raw, config)

	err = conn.Handshake()
	if err != nil {
		log.Println(err)

		errClose := conn.Close()
		if err != nil {
			log.Println(errClose)
		}

		errClose = raw.Close()
		if err != nil {
			log.Println(errClose)
		}

		return nil, fmt.Errorf(myerrors.ErrTemplate, err)
	}

	return conn, nil
}
