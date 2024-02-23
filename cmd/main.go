package main

import (
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/Vilinvil/hw-security-1/pkg/httputils"
	"github.com/Vilinvil/hw-security-1/pkg/myerrors"
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

const (
	HeaderProxyConnection = "Proxy-Connection"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Println(r)
		log.Println("______________________")

		err := SetForwardedHeader(r)
		if err != nil {
			return
		}

		r.Header.Del(HeaderProxyConnection)

		log.Println(r)

		log.Println("______________________")

		client := http.Client{}

		r.RequestURI = ""

		resp, err := client.Do(r)
		if err != nil {
			log.Println(err)

			return
		}

		defer resp.Body.Close()

		httputils.WriteOkHTTP(w, httputils.ConvertResponseToString(resp))
	})

	defer log.Println("me")

	log.Println("Server is running on port 8081")

	if err := http.ListenAndServe(":8081", mux); err != nil {
		log.Println(err)
	}
}
