package deliveryutil

import (
	"fmt"
	"net/http"
)

func FormatHeadersToString(headers http.Header) string {
	result := ""

	for header, values := range headers {
		result += fmt.Sprintf("%s: %v\n", header, values)
	}

	return result
}

func FormatBeginResponseToString(resp *http.Response) string {
	return fmt.Sprintf("%s %d %s \n%s",
		resp.Proto, resp.StatusCode, resp.Status, FormatHeadersToString(resp.Header))
}

func FormatBeginRequestToString(r *http.Request) string {
	return fmt.Sprintf("%s %s%s %s \n%s",
		r.Method, r.Host, r.URL.Path, r.Proto, FormatHeadersToString(r.Header))
}
