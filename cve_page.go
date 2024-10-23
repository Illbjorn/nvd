package nvd

// cvePage describes the JSON object returned by the 'rest/json/cves/2.0'
// endpoint.
type cvePage struct {
	Timestamp       timestamp `json:"timestamp"`
	Vulnerabilities []CVE     `json:"vulnerabilities"`
	ResultsPerPage  int       `json:"resultsPerPage"`
	StartIndex      int       `json:"startIndex"`
	TotalResults    int       `json:"totalResults"`
}
