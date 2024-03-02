package deliveryutil

import (
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/Vilinvil/hw-security-1/pkg/myerrors"
)

const connectionHeader = "Connection"

var hopByHopHeaders = []string{ //nolint:gochecknoglobals
	connectionHeader,
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeConnectionHeaders(header http.Header) {
	for _, field := range header[connectionHeader] {
		header.Del(field)
	}
}

func RemoveHopByHopHeaders(header http.Header) {
	removeConnectionHeaders(header)

	for _, hopByHopHeader := range hopByHopHeaders {
		header.Del(hopByHopHeader)
	}
}

var (
	RequestNil    = myerrors.NewError("request is nil")     //nolint:gochecknoglobals
	RequestURLNil = myerrors.NewError("request url is nil") //nolint:gochecknoglobals
)

const (
	acceptEncodingHeader = "Accept-Encoding"
	gzipHeader           = "gzip"
)

func setForwardedHeader(r *http.Request) error {
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

func ChangeRequestToTarget(r *http.Request, targetHost string) error {
	targetURL, err := convertAddrToURL(targetHost)
	if err != nil {
		return fmt.Errorf(myerrors.ErrTemplate, err)
	}

	err = setForwardedHeader(r)
	if err != nil {
		return fmt.Errorf(myerrors.ErrTemplate, err)
	}

	r.Header.Set(acceptEncodingHeader, gzipHeader)

	targetURL.Path = r.URL.Path
	targetURL.RawQuery = r.URL.RawQuery
	r.URL = targetURL
	r.RequestURI = ""

	return nil
}

func convertAddrToURL(addr string) (*url.URL, error) {
	if !strings.HasPrefix(addr, "https") && !strings.HasPrefix(addr, "http") {
		addr = "https://" + addr
	}

	fullURL, err := url.Parse(addr)
	if err != nil {
		log.Println(err)

		return nil, fmt.Errorf(myerrors.ErrTemplate, err)
	}

	return fullURL, nil
}

const headerContentEncoding = "Content-Encoding"

func ConvertRespBodyToReadCloserWithTryDecode(resp *http.Response) (io.ReadCloser, error) {
	if resp.Header.Get(headerContentEncoding) == gzipHeader {
		resp.Header.Del(headerContentEncoding)

		decodedReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			log.Println(err)

			return nil, fmt.Errorf(myerrors.ErrTemplate, err)
		}

		return decodedReader, nil
	}

	return resp.Body, nil
}
