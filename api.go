package nvd

const (
	// The standard path usedin all requests.
	// The NVD API only has a single endpoint.
	pathCVEsCVSSV2 = "rest/json/cves/2.0"
	// ISO-8601 time format string (required by NVD for start/end date ranges).
	timeFormatISO8601 = "2006-01-02T15:04:05.000Z"
	// The default results-per-page value.
	defaultResultsPerPage = 100
)

const (
	// The NVD CVE API offers a single request path (rest/json/cves/2.0),
	// filtering/refinement of returned data is controlled by the query string.
	// Below are known query keys made available via the NVD API.
	// https://nvd.nist.gov/developers/vulnerabilities
	//
	// queryKeyCPEName filters results to CVEs associated with a particular CPE
	// name.
	queryKeyCPEName = "cpeName"
	// queryKeyCVEID returns a single CVE with a matching ID, if it exists.
	queryKeyCVEID = "cveId"
	// queryKeyCVETag returns CVEs holding a matching tag.
	// Tags can be one of several predefined values, see the CVETag type for
	// these.
	queryKeyCVETag = "cveTag"
	// queryKeyCVSSV2Severity defines a minimum threshold for CVSS V2 severity -
	// see the CVSSV2Severity type for predefined values.
	queryKeyCVSSV2Severity = "cvssV2Severity"
	// queryKeyHasKEV produces only results which CISA has confirmed exploitation of in
	// the wild.
	queryKeyHasKEV = "hasKev"
	// queryKeyIsVulnerable produces only results where 1) a CPE is associated and
	// 2) the CPE is considered vulnerable.
	queryKeyIsVulnerable = "isVulnerable"
	// queryKeyKeywordSearch filter results by keyword(s)
	// example (single keyword)    : "keywordSearch=Windows"
	// example (multiple keywords) : "keywordSearch=Windows Mac Linux"
	queryKeyKeywordSearch = "keywordSearch"
	// queryKeyPubStartDate filters results PUBLISHED only after this date.
	// NOTE: if specified, you MUST ALSO specify pubEndDate.
	queryKeyPubStartDate = "pubStartDate"
	// queryKeyPubEndDate filters results PUBLISHED only before this date.
	// NOTE: if specified, you MUST ALSO specify pubStartDate.
	queryKeyPubEndDate = "pubEndDate"
	// queryKeyResultsPerPage describes the query string key which indicates the
	// number of results returned per request.
	queryKeyResultsPerPage = "resultsPerPage"
	// queryKeyStartIndex describes the index at which paginated results should
	// be returned from.
	queryKeyStartIndex = "startIndex"
)
