package deliveryutil

import (
	"fmt"
	"net/http"
)

func ConvertHeadersToString(headers http.Header) string {
	result := ""

	for header, values := range headers {
		result += fmt.Sprintf("%s: %v\n", header, values)
	}

	return result
}

func ConvertResponseToString(resp *http.Response) string {
	return fmt.Sprintf("%s %d %s \n%s",
		resp.Proto, resp.StatusCode, resp.Status, ConvertHeadersToString(resp.Header))
}

func ConvertRequestToString(r *http.Request) string {
	return fmt.Sprintf("%s %s %s \n%s",
		r.Method, r.URL.Path, r.Proto, ConvertHeadersToString(r.Header))
}
