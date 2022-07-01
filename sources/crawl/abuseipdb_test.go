package crawl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/shlin168/sdfinder/sources/base"
)

func NewMockServer(fpath string) *httptest.Server {
	return httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		content, err := os.ReadFile(fpath)
		if err != nil {
			http.Error(w, "read file error", http.StatusInternalServerError)
			return
		}
		w.Write(content)
	}))
}

func TestAbuseIPDB(t *testing.T) {
	testSrv := NewMockServer("testdata/abuseipdb.html")
	testSrv.Start()

	testURLBuilder := func(domain string) string { return fmt.Sprintf("%s/whois/", testSrv.URL) + domain }
	aid := NewAbuseIPDB()
	require.NoError(t, aid.Init(base.UrlBuilder(testURLBuilder)))
	subdomains, err := aid.Get(context.Background(), "bench.com")
	require.NoError(t, err)
	sort.Strings(subdomains)
	exp := []string{
		"adfs.bench.com", "aln-wsus01.bench.com", "ang-dns-int.bench.com", "ang-dns03-int.bench.com", "ang-dns03.bench.com",
		"autodiscover.bench.com", "autodiscover.secure.bench.com", "awtunnel.bench.com", "b2b-dev.bench.com", "b2b-prod.bench.com",
		"b2b-qa.bench.com", "b2b.bench.com", "bakerftp.bench.com", "bei-pnat-szc.bench.com", "bei-wsus01.bench.com",
		"bench-gw3.bench.com", "career.bench.com", "careers.bench.com", "collab.bench.com", "connect-apac.bench.com",
		"connect-dr.bench.com", "connect-eu.bench.com", "connect.bench.com", "corp-dmz-wsus01.bench.com", "corp-et02.bench.com",
		"corpedge.bench.com", "crm.bench.com", "customer.bench.com", "customervpn.bench.com", "dfm.bench.com",
		"dr-dns03-int.bench.com", "dr-dns03.bench.com", "dts.bench.com", "eftme.bench.com", "egspm.bench.com",
		"emerson-pen.bench.com", "emulexftp.bench.com", "exp1-us.bench.com", "ftp.bench.com", "guestwifi-ang.bench.com",
		"guestwifi-rcm.bench.com", "ir.bench.com", "its.bench.com", "its2.bench.com", "jabber.bench.com",
		"legacy.bench.com", "mag.bench.com", "mail.bench.com", "mcc-targetstats.bench.com", "navexsso.bench.com",
		"pen-wsus01.bench.com", "plm.bench.com", "pool-rcm.bench.com", "pt.bench.com", "sasprovision.bench.com",
		"secure.bench.com", "secureconnect-apac.bench.com", "secureconnect-dr.bench.com", "secureconnect-eu.bench.com",
		"secureconnect.bench.com", "seg.bench.com", "servicedesk.bench.com", "sftp.bench.com", "swix.bench.com",
		"syslog.bench.com", "targetstats.bench.com", "time2.bench.com", "time3.bench.com", "tmee.bench.com",
		"tmee2.bench.com", "vpn-as.bench.com", "vpn-dr.bench.com", "vpn-eu.bench.com", "vpn-ios.bench.com",
		"vpn.bench.com", "webmail-dr.bench.com", "webmail.bench.com", "win-wsus01.bench.com", "www.bench.com", "www.ir.bench.com"}

	assert.Equal(t, exp, subdomains)
	assert.Equal(t, aid.Stat.DomainsCnt, uint64(1))
	assert.Equal(t, aid.Stat.SuccessCnt, uint64(1))
	assert.Equal(t, aid.Stat.FoundCnt, uint64(1))
	assert.Equal(t, aid.Stat.RelatedDomainCnt, uint64(len(exp)))

	testSrv.Close()
}

func TestAbuseIPDBNotFound(t *testing.T) {
	testSrv := NewMockServer("testdata/abuseipdb_notfound.html")
	testSrv.Start()

	testURLBuilder := func(domain string) string { return fmt.Sprintf("%s/whois/", testSrv.URL) + domain }
	aid := NewAbuseIPDB()
	require.NoError(t, aid.Init(base.UrlBuilder(testURLBuilder)))
	subdomains, err := aid.Get(context.Background(), "abc.com")
	require.NoError(t, err)
	sort.Strings(subdomains)
	assert.Empty(t, subdomains)
	assert.Equal(t, aid.Stat.DomainsCnt, uint64(1))
	assert.Equal(t, aid.Stat.SuccessCnt, uint64(1))
	assert.Equal(t, aid.Stat.NotFoundCnt, uint64(1))
	assert.Equal(t, aid.Stat.RelatedDomainCnt, uint64(0))

	testSrv.Close()
}

func TestAbuseIPDBError(t *testing.T) {
	testSrv := NewMockServer("") // no file found
	testSrv.Start()

	testURLBuilder := func(domain string) string { return fmt.Sprintf("%s/whois/", testSrv.URL) + domain }
	aid := NewAbuseIPDB()
	require.NoError(t, aid.Init(base.UrlBuilder(testURLBuilder)))
	subdomains, err := aid.Get(context.Background(), "abc.com")
	assert.Error(t, err) // get 500
	assert.Empty(t, subdomains)
	assert.Equal(t, aid.Stat.DomainsCnt, uint64(1))
	assert.Equal(t, aid.Stat.ErrCnt, uint64(1))
	assert.Equal(t, aid.Stat.RelatedDomainCnt, uint64(0))

	testSrv.Close()
}
