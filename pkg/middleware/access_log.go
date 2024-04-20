package middleware

import (
	"bufio"
	"errors"
	"log"
	"net"
	"net/http"

	"github.com/Vilinvil/hw-security-1/pkg/deliveryutil"
)

type WriterWithStatus struct {
	http.ResponseWriter
	Status int
}

func (w *WriterWithStatus) WriteHeader(statusCode int) {
	w.Status = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

var ErrHijack = errors.New("ResponseWriter not implement Hijacker")

func (w *WriterWithStatus) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		log.Println(ErrHijack)

		return nil, nil, ErrHijack
	}

	return hj.Hijack()
}

func AccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("START REQ: \n", deliveryutil.FormatRequestToString(r))

		writerWithStatus := &WriterWithStatus{ResponseWriter: w, Status: http.StatusOK}

		next.ServeHTTP(writerWithStatus, r)

		log.Printf("END REQ: \n status: %d %s", writerWithStatus.Status, deliveryutil.FormatRequestToString(r))
	})
}
