package cert

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/shlin168/sdfinder/sources/base"
)

func NewMockServer() *httptest.Server {
	return httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		content := `[
			{
				"issuer_ca_id": 157938,
				"issuer_name": "C=US, O=\"Cloudflare, Inc.\", CN=Cloudflare Inc ECC CA-3",
				"common_name": "www.bench.com",
				"name_value": "www.bench.com",
				"id": 6698513836,
				"entry_timestamp": "2022-05-10T04:10:33.149",
				"not_before": "2022-05-10T00:00:00",
				"not_after": "2023-05-10T23:59:59",
				"serial_number": "0a1324f33307e51287fb65e5d411f20c"
			},
			{
				"issuer_ca_id": 157939,
				"issuer_name": "C=US, O=\"Cloudflare, Inc.\", CN=Cloudflare Inc RSA CA-2",
				"common_name": "www.bench.com",
				"name_value": "www.bench.com",
				"id": 6698513850,
				"entry_timestamp": "2022-05-10T04:10:32.415",
				"not_before": "2022-05-10T00:00:00",
				"not_after": "2023-05-10T23:59:59",
				"serial_number": "0a3c43e6e24b6842e3aa1cfd9682eca5"
			},
			{
				"issuer_ca_id": 185756,
				"issuer_name": "C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1",
				"common_name": "secureconnect-dr.bench.com",
				"name_value": "secureconnect-dr.bench.com",
				"id": 6347527490,
				"entry_timestamp": "2022-03-15T16:36:58.438",
				"not_before": "2022-03-15T00:00:00",
				"not_after": "2023-03-15T23:59:59",
				"serial_number": "07e18169552ab4feea83dcd239df2456"
			},
			{
				"issuer_ca_id": 185756,
				"issuer_name": "C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1",
				"common_name": "connect-dr.bench.com",
				"name_value": "connect-dr.bench.com",
				"id": 6347522960,
				"entry_timestamp": "2022-03-15T16:35:59.274",
				"not_before": "2022-03-15T00:00:00",
				"not_after": "2023-03-15T23:59:59",
				"serial_number": "012992f1480abd0ae91101bb9273b7fe"
			},
			{
				"issuer_ca_id": 904,
				"issuer_name": "C=US, ST=Arizona, L=Scottsdale, O=\"GoDaddy.com, Inc.\", OU=http://certs.godaddy.com/repository/, CN=Go Daddy Secure Certificate Authority - G2",
				"common_name": "targetstats.bench.com",
				"name_value": "targetstats.bench.com\nwww.targetstats.bench.com",
				"id": 6212191392,
				"entry_timestamp": "2022-02-20T07:13:59.452",
				"not_before": "2022-02-20T07:13:58",
				"not_after": "2022-04-28T23:05:53",
				"serial_number": "07c609d8d5285706"
			},
			{
				"issuer_ca_id": 904,
				"issuer_name": "C=US, ST=Arizona, L=Scottsdale, O=\"GoDaddy.com, Inc.\", OU=http://certs.godaddy.com/repository/, CN=Go Daddy Secure Certificate Authority - G2",
				"common_name": "unusedguestwifi-ang.bench.com",
				"name_value": "unusedguestwifi-ang.bench.com\nwww.unusedguestwifi-ang.bench.com",
				"id": 6047629081,
				"entry_timestamp": "2022-01-25T18:51:17.494",
				"not_before": "2022-01-25T18:51:05",
				"not_after": "2023-02-26T18:51:05",
				"serial_number": "29c4fec1fefc0310"
			},
			{
				"issuer_ca_id": 904,
				"issuer_name": "C=US, ST=Arizona, L=Scottsdale, O=\"GoDaddy.com, Inc.\", OU=http://certs.godaddy.com/repository/, CN=Go Daddy Secure Certificate Authority - G2",
				"common_name": "guestwifi-rcm.bench.com",
				"name_value": "guestwifi-rcm.bench.com\nwww.guestwifi-rcm.bench.com",
				"id": 6047628975,
				"entry_timestamp": "2022-01-25T18:51:02.889",
				"not_before": "2022-01-25T18:50:50",
				"not_after": "2023-02-26T18:50:50",
				"serial_number": "5c95880d1c555320"
			}
		]`
		w.Write([]byte(content))
	}))
}

func TestCrtsh(t *testing.T) {
	testSrv := NewMockServer()
	testSrv.Start()

	testURLBuilder := func(domain string) string { return fmt.Sprintf("%s/?output=json&q=", testSrv.URL) + domain }
	crtsh := NewCrtsh()
	require.NoError(t, crtsh.Init(base.UrlBuilder(testURLBuilder)))
	subdomains, err := crtsh.Get(context.Background(), "bench.com")
	require.NoError(t, err)
	sort.Strings(subdomains)
	exp := []string{
		"connect-dr.bench.com",
		"guestwifi-rcm.bench.com",
		"secureconnect-dr.bench.com",
		"targetstats.bench.com", // certificate of this subdomains is expired
		"unusedguestwifi-ang.bench.com",
		"www.bench.com",
		"www.guestwifi-rcm.bench.com",
		"www.targetstats.bench.com",
		"www.unusedguestwifi-ang.bench.com",
	}
	assert.Equal(t, exp, subdomains)
	assert.Equal(t, crtsh.Stat.DomainsCnt, uint64(1))
	assert.Equal(t, crtsh.Stat.SuccessCnt, uint64(1))
	assert.Equal(t, crtsh.Stat.FoundCnt, uint64(1))
	assert.Equal(t, crtsh.Stat.RelatedDomainCnt, uint64(len(exp)))

	// with TimeAfter to filter expired certificate
	crtsh = NewCrtsh()
	require.NoError(t, crtsh.Init(base.UrlBuilder(testURLBuilder), base.TimeAfter(time.Date(2022, 5, 31, 0, 0, 0, 0, time.UTC))))
	subdomains, err = crtsh.Get(context.Background(), "bench.com")
	require.NoError(t, err)
	sort.Strings(subdomains)
	exp = []string{
		"connect-dr.bench.com",
		"guestwifi-rcm.bench.com",
		"secureconnect-dr.bench.com",
		"unusedguestwifi-ang.bench.com",
		"www.bench.com",
		"www.guestwifi-rcm.bench.com",
		"www.unusedguestwifi-ang.bench.com",
	}
	assert.Equal(t, exp, subdomains)
	assert.Equal(t, crtsh.Stat.DomainsCnt, uint64(1))
	assert.Equal(t, crtsh.Stat.SuccessCnt, uint64(1))
	assert.Equal(t, crtsh.Stat.FoundCnt, uint64(1))
	assert.Equal(t, crtsh.Stat.RelatedDomainCnt, uint64(len(exp)))

	testSrv.Close()
}

func TestCrtshTimeout(t *testing.T) {
	testSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		time.Sleep(1 * time.Second)
		w.Write([]byte("timeout"))
	}))
	testSrv.Start()

	testURLBuilder := func(domain string) string { return fmt.Sprintf("%s/?output=json&q=", testSrv.URL) + domain }
	crtsh := NewCrtsh()
	require.NoError(t, crtsh.Init(base.UrlBuilder(testURLBuilder), base.Timeout(1*time.Millisecond)))
	subdomains, err := crtsh.Get(context.Background(), "bench.com")
	assert.Error(t, err)
	assert.True(t, os.IsTimeout(err))
	assert.Empty(t, subdomains)

	assert.Equal(t, crtsh.Stat.DomainsCnt, uint64(1))
	assert.Equal(t, crtsh.Stat.TimeoutCnt, uint64(1))
	assert.Equal(t, crtsh.Stat.RelatedDomainCnt, uint64(0))

	testSrv.Close()
}
