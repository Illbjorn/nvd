package nvd

import (
	"encoding/json"
	"io"
	"net/http"
	"time"
)

var (
	apiRequestScheme = "https"
	apiHostname      = "services.nvd.nist.gov"

	client = http.Client{Timeout: 5 * time.Second}
)

func do(r *http.Request) ([]byte, error) {
	// Execute the request.
	response, err := client.Do(r)
	if err != nil {
		return nil, err
	}
	// Defer body disposal.
	defer response.Body.Close()

	// Read the response body and return.
	return io.ReadAll(response.Body)
}

func doWithUnmarshal[T any](r *http.Request) (T, error) {
	var ret T

	// Execute the request.
	resp, err := do(r)
	if err != nil {
		return ret, err
	}

	// Attempt response body deserialize.
	err = json.Unmarshal(resp, &ret)
	return ret, err
}
