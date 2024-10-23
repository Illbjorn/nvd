package nvd

// cveTag describes a set of optional pre-defined values which describe some
// meta-topics associated with CVEs. See individual descriptions below.
// https://nvd.nist.gov/vuln/vulnerability-detail-pages
type cveTag string

const (
	// cveTagDisputed indicates at least one party has asserted this discovery
	// constitutes a vulnerability and at least one party has asserted this
	// discovery does NOT constitute a vulnerability
	cveTagDisputed cveTag = "disputed"
	// cveTagUnsupportedWhenAssigned indicates the product/product-version
	// impacted by the CVE was already considered end of life when the CVE
	// discovery was made.
	cveTagUnsupportedWhenAssigned cveTag = "unsupported-when-assigned"
	// cveTagExclusivelyHostedService indicates the product offers a self AND
	// SaaS hosted solution and that only the hosted solution is impacted.
	cveTagExclusivelyHostedService cveTag = "exclusively-hosted-service"
)
