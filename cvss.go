package nvd

import (
	"bytes"
	"fmt"
)

// cvssMetricV2 describes metadata associated with a CVE's CVSS V2 scoring.
type cvssMetricV2 struct {
	Source              string         `json:"source"`
	Type                string         `json:"type"`
	BaseSeverity        cvssSeverityV2 `json:"baseSeverity"`
	CVSSData            cvssData       `json:"cvssData"`
	ExploitabilityScore float32        `json:"exploitabilityScore"`
	ImpactScore         float32        `json:"impactScore"`
}

// cvssSeverityV2 describes one of a set of pre-defined values indicating
// thresholds of vulnerability signficance.
type cvssSeverityV2 string

const (
	severityHigh cvssSeverityV2 = "HIGH"
	severityMed  cvssSeverityV2 = "MEDIUM"
	severityLow  cvssSeverityV2 = "LOW"
)
var (

	bArrSpace = []byte(" ")
	bArrQuote = []byte("\"")
	bArrEmpty = []byte("")
)

// UnmarshalJSON fulfills the json.Unmarshaler interface to ensure the received
// value is parsed as a true CVSSSeverityV2 type and is valid.
func (s *cvssSeverityV2) UnmarshalJSON(b []byte) (err error) {
	// throw away unnecessary characters
	b = bytes.ReplaceAll(b, bArrQuote, bArrEmpty)
	b = bytes.ReplaceAll(b, bArrSpace, bArrEmpty)

	// severity cast the byte slice
	*s = cvssSeverityV2(b)

	// confirm the received value is inline with expected values
	switch *s {
	case severityHigh, severityMed, severityLow:
		return nil
	default:
		return fmt.Errorf("unexpected CVSSSeverityV2 value '%s'", *s)
	}
}

// cvssData is primarily implemented currently to reach the BaseScore field
// which contains a 0.0-10.0 value indicating a general vulnerability
// significance.
type cvssData struct {
	Version   string  `json:"version"`
	BaseScore float32 `json:"baseScore"`
}
