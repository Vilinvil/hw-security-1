package httputils

import (
	"log"
	"net/http"
)

const InternalErrorMessage = "Внутрення ошибка на сервере"

func WriteErrorHTTP(w http.ResponseWriter, httpStatus int, message string) {
	w.WriteHeader(httpStatus)

	_, err := w.Write([]byte(message))
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
