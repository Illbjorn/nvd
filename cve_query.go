package nvd

// TODO: implement CVSS v2 and v3 severities - these are implemented but not yet
//       supported by the NVD API.

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

var (
	itoa = strconv.Itoa
)

// NewCVEQuery initializes a boilerplate CVEQuery instance.
//
// Example:
//
//	cves, err := NewCVEQuery().ResultsPerPage(100).Keyword("Mac").Fetch()
func NewCVEQuery() CVEQuery {
	q := CVEQuery{
		values: url.Values{},
		qURL: url.URL{
			Scheme: apiRequestScheme,
			Host:   apiHostname,
			Path:   pathCVEsCVSSV2,
		},
	}

	// set a default 'resultsPerPage' value
	return q.ResultsPerPage(defaultResultsPerPage)
}

// CVEQuery serves as a query builder for retrieving CVE data from the Nist
// Vulnerability Database (NVD).
type CVEQuery struct {
	values          url.Values
	qURL            url.URL
	publishedWithin time.Duration
}

var _ fmt.Stringer = CVEQuery{}

func (cq CVEQuery) String() string {
	return cq.qURL.RawQuery
}

// Fetch executes the currently constructed CVE query, returning all identified
// CVEs.
func (cq CVEQuery) Fetch() ([]CVE, error) {
	// get the url
	u := cq.qURL

	// Apply a published start/end if we have a duration.
	if cq.publishedWithin != 0 {
		end := time.Now()
		start := end.Add(-cq.publishedWithin)
		cq.values.Set(queryKeyPubStartDate, start.Format(timeFormatISO8601))
		cq.values.Set(queryKeyPubEndDate, end.Format(timeFormatISO8601))
	}
	u.RawQuery = cq.values.Encode()

	// Collect and return all CVEs.
	return cq.getCVEs(u)
}

func (cq *CVEQuery) getCVEs(qURL url.URL) ([]CVE, error) {
	var cves []CVE

	for {
		// Init the request.
		r, err := http.NewRequest(http.MethodGet, qURL.String(), nil)
		if err != nil {
			return cves, err
		}

		// Execute the request and attempt to deserialize the result to a cvePage.
		result, err := doWithUnmarshal[cvePage](r)
		if err != nil {
			return cves, err
		}

		// Return early on no results.
		if result.TotalResults == 0 {
			return nil, ErrNoResults
		}

		// Append the collected CVEs.
		cves = append(cves, result.Vulnerabilities...)

		// Define next page starting index.
		nextStartIndex := result.StartIndex + result.ResultsPerPage

		// Return when we run out of results.
		if nextStartIndex >= result.TotalResults {
			return cves, nil
		}

		// Move the query 'startIndex' forward for the next page.
		q := qURL.Query()
		q.Set(queryKeyStartIndex, itoa(nextStartIndex))
		qURL.RawQuery = q.Encode()
	}
}

// ResultsPerPage allows tuning of the number of CVEs which will be returned
// per paginated request.
func (cq CVEQuery) ResultsPerPage(n int) CVEQuery {
	cq.values.Set(queryKeyResultsPerPage, itoa(n))
	return cq
}

// CPEName allows filtering of results to CVEs associated with a particular
// CPE.
func (cq CVEQuery) CPEName(name string) CVEQuery {
	cq.values.Set(queryKeyCPEName, name)
	return cq
}

// CVEID retrieves a single CVE with the provided ID.
func (cq CVEQuery) CVEID(id string) CVEQuery {
	cq.values.Set(queryKeyCVEID, id)
	return cq
}

// CVETag filters results to only those associated with a given tag.
// NOTE: only a SINGLE tag can be provided via this query at a time.
func (cq CVEQuery) CVETag(tag cveTag) CVEQuery {
	cq.values.Set(queryKeyCVETag, string(tag))
	return cq
}

// CVSSV2Severity filters results to only those that meet the provided MINIMUM
// CVSS V2 severity threshold.
func (cq CVEQuery) CVSSV2Severity(severity cvssSeverityV2) CVEQuery {
	cq.values.Set(queryKeyCVSSV2Severity, string(severity))
	return cq
}

// PublishedWithin filters results to only those published AFTER time.Time start
// and before time.Time end.
func (cq CVEQuery) PublishedWithin(duration time.Duration) CVEQuery {
	cq.publishedWithin = duration
	return cq
}

// KeywordSearch filters results to only those containing one or more keywords.
//
// NOTE: multiple keywords are provided by space-delimiting them within a SINGLE
// string.
//
// Examples:
// q.KeywordSearch("Cisco")
// q.KeywordSearch("Mac Windows")
func (cq CVEQuery) KeywordSearch(keyword string) CVEQuery {
	cq.values.Set(queryKeyKeywordSearch, keyword)
	return cq
}
