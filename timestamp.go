package nvd

import (
	"strings"
	"time"
)

// timestamp encloses a standard time.Time struct, implementing
// json.Unmarshaler to produce a proper time.Time instance parsed from the NVD's
// ISO-8601 format.
type timestamp struct {
	time.Time
}

// the time format returned in the 'timestamp' field of a vulnerability from the
// NVD CVE API.
const timeFormatNVDAPI = "2006-01-02T15:04:05.999999"

// UnmarshalJSON implements json.Unmarshaler to properly parse the time format
// returned by NVD CVE API results to time.Time.
func (t *timestamp) UnmarshalJSON(b []byte) (err error) {
	// remove quotation marks
	timeStr := strings.ReplaceAll(string(b), "\"", "")
	// perform the parse
	t.Time, err = time.Parse(timeFormatNVDAPI, timeStr)

	return err
}
