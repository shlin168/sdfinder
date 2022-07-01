package cert

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/shlin168/sdfinder/sources/base"
)

// https://crt.sh/?output=json&q=<domain>
// fetch "name_value" field from each json item in json list
/*{
    "issuer_ca_id": 904,
    "issuer_name": "...",
    "common_name": "<cert domain>",
    "name_value": "<sans subdomain>\n<sans subdomain>",
    "id": 5593809543,
    "entry_timestamp": "2021-11-12T20:36:13.709",
    "not_before": "2021-11-12T20:36:11",
    "not_after": "2022-12-14T20:36:11",
    "serial_number": "2501d43f7efc94fe"
}*/
const NameCrtsh = "crtsh"

func init() {
	base.MustRegister(NameCrtsh, NewCrtsh())
}

type Crtsh struct{ base.SDFinder }
type CrtshRsp struct {
	IssuerCaID int      `json:"issuer_ca_id"`
	CommonName string   `json:"common_name"`
	NameValue  string   `json:"name_value"` // subdomains sep by '\n'
	NotAfter   MsgTime  `json:"not_after"`
	Subdomains []string `json:"-"`
}

func NewCrtsh() *Crtsh {
	return &Crtsh{*base.NewSDFinder()}
}

func (c *Crtsh) Init(opts ...base.Option) error {
	c.URLbuilder = func(domain string) string {
		return "https://crt.sh/?output=json&q=" + domain
	}
	c.Parse = func(content []byte) ([]string, error) {
		var rsp []CrtshRsp
		if err := json.Unmarshal(content, &rsp); err != nil {
			return nil, err
		}
		var subdomains []string
		for _, certificate := range rsp {
			if !c.TimeAfter.IsZero() {
				if certificate.NotAfter.IsZero() || certificate.NotAfter.Before(c.TimeAfter) {
					// skip if 'not_after' can not be parsed or if it's before now, which means this certificate is expired
					continue
				}
			}
			for _, subdomain := range strings.Split(certificate.NameValue, "\n") {
				if len(subdomain) > 0 {
					subdomains = append(subdomains, subdomain)
				}
			}
			// value of CommonName can be subdomain or related domains
			subdomains = append(subdomains, certificate.CommonName)
		}
		return subdomains, nil
	}
	return c.SDFinder.Init(opts...)
}

func (c Crtsh) RelatedMethod() string {
	return base.FromCert
}

func (c Crtsh) Name() string {
	return NameCrtsh
}

// MsgTimeFmt is the time format for 'not_after' and 'not_before' fields in crt.sh
const MsgTimeFmt = "2006-01-02T15:04:05"

type MsgTime time.Time

func (t *MsgTime) UnmarshalJSON(data []byte) (err error) {
	newTime, err := time.Parse("\""+MsgTimeFmt+"\"", string(data))
	*t = MsgTime(newTime)
	return
}

func (t MsgTime) MarshalJSON() ([]byte, error) {
	timeStr := fmt.Sprintf("\"%s\"", time.Time(t).Format(MsgTimeFmt))
	return []byte(timeStr), nil
}

func (t MsgTime) IsZero() bool {
	return time.Time(t).IsZero()
}

func (t MsgTime) Before(c time.Time) bool {
	return time.Time(t).Before(c)
}
