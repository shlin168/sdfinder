package crawl

import (
	"bytes"
	"context"

	"github.com/PuerkitoBio/goquery"

	"github.com/shlin168/sdfinder/sources/base"
)

// https://www.abuseipdb.com/whois/<domain>
// rate limit: ?
const NameAbuseIPDB = "abuseipdb"

func init() {
	base.MustRegister(NameAbuseIPDB, NewAbuseIPDB())
}

type AbuseIPDB struct{ base.SDFinder }

func NewAbuseIPDB() *AbuseIPDB {
	return &AbuseIPDB{*base.NewSDFinder()}
}

func (aid *AbuseIPDB) Init(opts ...base.Option) error {
	aid.URLbuilder = func(domain string) string {
		return "https://www.abuseipdb.com/whois/" + domain
	}
	aid.Parse = func(content []byte) ([]string, error) {
		var result []string
		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(content))
		if err != nil {
			return nil, err
		}
		doc.Find(`h4`).Each(func(_ int, s *goquery.Selection) {
			if s.Text() == "Subdomains" {
				s.Next().Find(`ul li`).Each(func(_ int, sd *goquery.Selection) {
					if len(sd.Text()) > 0 {
						result = append(result, sd.Text())
					}
				})
			}
		})
		return result, nil
	}
	return aid.SDFinder.Init(opts...)
}

func (aid AbuseIPDB) RelatedMethod() string {
	return base.FromCrawl
}

func (aid AbuseIPDB) Name() string {
	return NameAbuseIPDB
}

func (aid *AbuseIPDB) Get(ctx context.Context, domain string) (subdomains []string, err error) {
	subdomainPrefixs, err := aid.SDFinder.Get(ctx, domain)
	if err != nil {
		return subdomains, err
	}
	for _, fstlvl := range subdomainPrefixs {
		subdomains = append(subdomains, fstlvl+"."+domain)
	}
	return subdomains, nil
}
