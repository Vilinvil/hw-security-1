package deliveryutil

import (
	"fmt"
	"log"
	"net"
	"net/http"
)

const InternalErrorMessage = "Внутрення ошибка на сервере"

func WriteRawResponseHTTP1(connect net.Conn, message string, statusCode int) {
	_, err := connect.Write([]byte(fmt.Sprintf(`HTTP/1.1 %d %s\r\n\r\n`, statusCode, message)))
	if err != nil {
		log.Println(err)
	}
}

func WriteSlByte(w http.ResponseWriter, message []byte) {
	_, err := w.Write(message)
	if err != nil {
		log.Println(err)
	}
}

func WriteOkHTTP(w http.ResponseWriter, message string) {
	w.WriteHeader(http.StatusOK)
	WriteSlByte(w, []byte(message))
}
