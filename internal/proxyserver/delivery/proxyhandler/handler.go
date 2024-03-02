package proxyhandler

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
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
	log.Println(deliveryutil.ConvertBeginRequestToString(r), "\n______________________")

	if r.Method == http.MethodConnect {
		p.handleTunneling(w, r)

		return
	}

	p.handleRequest(w, r)
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

var ErrUncorrectedHost = myerrors.NewError("не правильный HOST в запросе")

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

	clientConn, err := hijackClientConnection(w)
	if err != nil {
		deliveryutil.WriteRawResponseHTTP1(clientConn, deliveryutil.InternalErrorMessage, http.StatusInternalServerError)

		return
	}

	tlsConn := tls.Server(clientConn, p.tlsServerConfig)
	defer func() {
		err = tlsConn.Close()
		if err != nil {
			log.Println(err)
		}
	}()

	connReader := bufio.NewReader(tlsConn)

	for {
		err = p.doOneExchangeReqResp(connReader, tlsConn, r.Host)
		if err != nil {
			break
		}
	}
}

func (p *ProxyHandler) doOneExchangeReqResp(connReader *bufio.Reader, conn net.Conn, targetHost string) error {
	reqToTarget, err := http.ReadRequest(connReader)
	if errors.Is(err, io.EOF) {
		return io.EOF
	} else if err != nil {
		log.Println(err)
		deliveryutil.WriteRawResponseHTTP1(conn, deliveryutil.InternalErrorMessage, http.StatusInternalServerError)

		return fmt.Errorf(myerrors.ErrTemplate, err)
	}

	log.Println(deliveryutil.ConvertBeginRequestToString(reqToTarget), "\n______________________")

	err = changeRequestToTarget(reqToTarget, targetHost)
	if err != nil {
		deliveryutil.WriteRawResponseHTTP1(conn, ErrUncorrectedHost.Error(), http.StatusBadRequest)

		return fmt.Errorf(myerrors.ErrTemplate, err)
	}

	resp, err := p.client.Do(reqToTarget)
	if err != nil {
		log.Println(err)
		deliveryutil.WriteRawResponseHTTP1(conn, deliveryutil.InternalErrorMessage, http.StatusInternalServerError)

		return fmt.Errorf(myerrors.ErrTemplate, err)
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			log.Println(err)
		}
	}()

	if err := resp.Write(conn); err != nil {
		log.Println(err)
		deliveryutil.WriteRawResponseHTTP1(conn, deliveryutil.InternalErrorMessage, http.StatusInternalServerError)

		return fmt.Errorf(myerrors.ErrTemplate, err)
	}

	return nil
}

func changeRequestToTarget(req *http.Request, targetHost string) error {
	targetURL, err := convertAddrToURL(targetHost)
	if err != nil {
		return fmt.Errorf(myerrors.ErrTemplate, err)
	}

	targetURL.Path = req.URL.Path
	targetURL.RawQuery = req.URL.RawQuery
	req.URL = targetURL
	req.RequestURI = ""

	return nil
}

func convertAddrToURL(addr string) (*url.URL, error) {
	if !strings.HasPrefix(addr, "https") {
		addr = "https://" + addr
	}

	fullURL, err := url.Parse(addr)
	if err != nil {
		log.Println(err)

		return nil, fmt.Errorf(myerrors.ErrTemplate, err)
	}

	return fullURL, nil
}

var ErrHijacker = myerrors.NewError("error type assert Hijacker")

const okResponse = "HTTP/1.1 200 OK\r\n\r\n"

func hijackClientConnection(w http.ResponseWriter) (net.Conn, error) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Println(ErrHijacker)
		http.Error(w, deliveryutil.InternalErrorMessage, http.StatusInternalServerError)

		return nil, fmt.Errorf(myerrors.ErrTemplate, ErrHijacker)
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Println(err)
		deliveryutil.WriteRawResponseHTTP1(clientConn, deliveryutil.InternalErrorMessage, http.StatusInternalServerError)

		return nil, fmt.Errorf(myerrors.ErrTemplate, err)
	}

	if _, err = clientConn.Write([]byte(okResponse)); err != nil {
		log.Println(err)
		deliveryutil.WriteRawResponseHTTP1(clientConn, deliveryutil.InternalErrorMessage, http.StatusInternalServerError)

		errClose := clientConn.Close()
		if err != nil {
			log.Println(errClose)
		}

		return nil, fmt.Errorf(myerrors.ErrTemplate, err)
	}

	return clientConn, nil
}

func (p *ProxyHandler) handleRequest(w http.ResponseWriter, r *http.Request) {
	err := deliveryutil.SetForwardedHeader(r)
	if err != nil {
		return
	}

	deliveryutil.RemoveHopByHopHeaders(r.Header)
	r.RequestURI = ""

	resp, err := p.client.Do(r)
	if err != nil {
		log.Println(err)
		http.Error(w, deliveryutil.InternalErrorMessage, http.StatusInternalServerError)

		return
	}

	deliveryutil.RemoveHopByHopHeaders(resp.Header)
	deliveryutil.WriteOkHTTP(w, deliveryutil.ConvertBeginResponseToString(resp))

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
