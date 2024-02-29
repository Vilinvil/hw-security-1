package deliveryutil

import (
	"log"
	"net/http"
)

const InternalErrorMessage = "Внутрення ошибка на сервере"

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
