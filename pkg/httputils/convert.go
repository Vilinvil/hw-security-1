package httputils

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
	return fmt.Sprintf(`%s %d %s
%+v`, resp.Proto, resp.StatusCode, resp.Status, ConvertHeadersToString(resp.Header))
}
