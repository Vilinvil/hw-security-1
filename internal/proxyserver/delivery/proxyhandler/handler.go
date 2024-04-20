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

func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Println("ACCESS LOG: \n", deliveryutil.FormatBeginRequestToString(r))

	if r.Method == http.MethodConnect {
		p.handleTunneling(w, r)

		return
	}

	p.handleRequest(w, r)
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
		err = p.doOneExchangeReqResp(connReader, tlsConn, r.Host, r.RemoteAddr)
		if err != nil {
			break
		}
	}
}

func (p *ProxyHandler) handleRequest(w http.ResponseWriter, r *http.Request) {
	err := deliveryutil.ChangeRequestToTarget(r, r.Host)
	if err != nil {
		http.Error(w, deliveryutil.InternalErrorMessage, http.StatusInternalServerError)

		return
	}

	resp, err := p.client.Do(r)
	if err != nil {
		log.Println(err)
		http.Error(w, deliveryutil.InternalErrorMessage, http.StatusInternalServerError)

		return
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			log.Println(err)
		}
	}()

	deliveryutil.RemoveHopByHopHeaders(resp.Header)
	deliveryutil.AddAllHeaders(w, resp.Header)

	var preparedBody io.ReadCloser

	if !deliveryutil.IsAcceptGzip(r) {
		preparedBody, err = deliveryutil.ConvertRespBodyToReadCloserWithTryDecode(resp)
		if err != nil {
			log.Println(err)
			http.Error(w, deliveryutil.InternalErrorMessage, http.StatusInternalServerError)

			return
		}
	} else {
		preparedBody = resp.Body
	}

	defer func() {
		err = preparedBody.Close()
		if err != nil {
			log.Println(err)
		}
	}()

	_, err = io.Copy(w, preparedBody)
	if err != nil {
		log.Println(err)
		http.Error(w, deliveryutil.InternalErrorMessage, http.StatusInternalServerError)

		return
	}
}

func (p *ProxyHandler) doOneExchangeReqResp(connReader *bufio.Reader,
	conn net.Conn, targetHost string, remoteAddr string,
) error {
	reqToTarget, err := http.ReadRequest(connReader)
	if errors.Is(err, io.EOF) {
		return io.EOF
	} else if err != nil {
		log.Println(err)
		deliveryutil.WriteRawResponseHTTP1(conn, deliveryutil.InternalErrorMessage, http.StatusInternalServerError)

		return fmt.Errorf(myerrors.ErrTemplate, err)
	}

	reqToTarget.RemoteAddr = remoteAddr

	err = deliveryutil.ChangeRequestToTarget(reqToTarget, targetHost)
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

	deliveryutil.RemoveHopByHopHeaders(resp.Header)

	if !deliveryutil.IsAcceptGzip(reqToTarget) {
		preparedBody, err := deliveryutil.ConvertRespBodyToReadCloserWithTryDecode(resp)
		if err != nil {
			log.Println(err)
			deliveryutil.WriteRawResponseHTTP1(conn, deliveryutil.InternalErrorMessage, http.StatusInternalServerError)

			return fmt.Errorf(myerrors.ErrTemplate, err)
		}

		resp.Body = preparedBody
	}

	if err = resp.Write(conn); err != nil {
		log.Println(err)
		deliveryutil.WriteRawResponseHTTP1(conn, deliveryutil.InternalErrorMessage, http.StatusInternalServerError)

		return fmt.Errorf(myerrors.ErrTemplate, err)
	}

	return nil
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
