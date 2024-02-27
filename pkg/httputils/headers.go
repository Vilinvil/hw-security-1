package httputils

import (
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/Vilinvil/hw-security-1/pkg/myerrors"
)

const (
	HeaderProxyConnection = "Proxy-Connection"
)

var (
	RequestNil    = myerrors.NewError("request is nil")     //nolint:gochecknoglobals
	RequestURLNil = myerrors.NewError("request url is nil") //nolint:gochecknoglobals
)

func SetForwardedHeader(r *http.Request) error {
	if r == nil {
		log.Println(RequestNil)

		return RequestNil
	}

	if r.URL == nil {
		log.Println(RequestURLNil)

		return RequestURLNil
	}

	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Println(err)

		return fmt.Errorf(myerrors.ErrTemplate, err)
	}

	valueForwardedHeader := fmt.Sprintf("for=%s;host=%s;proto=%s", clientIP, r.Host, r.URL.Scheme)
	r.Header.Set("Forwarded", valueForwardedHeader)

	return nil
}
