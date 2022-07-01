# Subdomains and related domains finder
[![build](https://github.com/shlin168/sdfinder/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/shlin168/sdfinder/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/shlin168/sdfinder/branch/master/graph/badge.svg)](https://codecov.io/gh/shlin168/sdfinder)

Given domains, try to find subdomains and related domains by querying or crawling from multiple sources. Support different query rate, timeout, concurrency and retries for each sources.

## Available sources
| Source                                                 | type   | name                     | input  | Note                                             |
|--------------------------------------------------------|--------|--------------------------| -------| -------------------------------------------------|
| [HackerTarget](https://hackertarget.com)               | api    | `hackertarget`           | domain | limit quota and max 500 subdomains for free user |
| [SonarSearch](https://github.com/Cgboal/SonarSearch)   | api    | `sonarsearch/subdomains` | domain | api to find subdomains for given domain          |
| [SonarSearch](https://github.com/Cgboal/SonarSearch)   | api    | `sonarsearch/reverse`    | ip     | api to find domains with same given ip           |
| [Sublist3r](https://github.com/aboul3la/Sublist3r)     | api    | `sublist3r`              | domain |                                                  |
| [ThreatCrowd](https://github.com/AlienVault-OTX/ApiV2) | api    | `threatcrowd`            | domain | max 500 subdomains                               |
| [crtsh (API)](https://crt.sh)                          | cert   | `crtsh`                  | domain | contains not only subdomains                     |
| [AbuseIPDB](https://www.abuseipdb.com)                 | crawl  | `abuseipdb`              | domain |                                                  |

## Build
```bash
mkdir bin
go build -o bin/ ./...
```

## Usage
### Input
Support either domains join by `','` from command line or file with domain in each line
1. given from command line
```bash
./sdfinder -d google.com,twitter.com -out out.json
```

2. given by file
```bash
./sdfinder -src domain.txt -out out.json
```
content in `domain.txt`
```
google.com
twitter.com
```

### Resolve IP
For `sonarsearch/reverse`, it returns domains with given IP. If `-ip` flag is given, all the input domains will be resolved to get IPs and query sonarsearch reverse API to find more related domains.
```
./sdfinder -d google.com,twitter.com -ip -out out.json
```

### Specify sources
1. `-q` limits to only use some of available sources. Eg., To only query `crtsh` and `abuseipdb`
```bash
./sdfinder -d google.com -out out.json -q crtsh,abuseipdb
```

2. Limit from config file
```bash
./sdfinder -d google.com -out out.json -cfg config.yaml
```

`config.yaml`
```yaml
enabled:
  - crtsh
  - abuseipdb
```

> when `-cfg=<config_path>` is given, `-q` will be skipped

### Custom config to query sources
Define config in file for each sources, using default if not given. E.g., with below command and config, `crtsh` use the custom config and `abuseipdb` use default config.
```bash
./sdfinder -d google.com -out out.json -cfg config.yaml
```

`config.yaml`
```yaml
enabled:          # mandatory
  - crtsh
  - abuseipdb
sources:          # optional
  crtsh:
    qps: 0.1      # mandatory
    timeout: 30s  # mandatory
    worker: 5     # mandatory
    retries:      # optional
      times: 1
      interval: 0.5s
```

### Concurrency
If `-cfg=<config_path>` is not given, `-worker`(default: 1) controls the amount of goroutines to handle the queries for each sources. E.g, if `-worker=4 -q=crtsh,abuseipdb` is given, it will start 8 goroutines in total. (4 for `crtsh` and 4 for `abuseipdb`)

> when `-cfg=<config_path>` is given, `-worker` will be skipped

```bash
./sdfinder -d google.com,twitter.com -out out.json -worker 4
```

## Statistic
The statistic information is print in log such as below
```bash
$ ./bin/sdfinder -d netflix.com -out out.json -q sonarsearch/subdomains,abuseipdb
INFO[0000] config file not given, using default config for sources
INFO[0000] flag                                          domains=netflix.com out=out.json queriers="sonarsearch/subdomains,abuseipdb" resolve-ip=false worker=1
INFO[0000] init queriers: [sonarsearch/subdomains abuseipdb]
INFO[0001] [unique] domain: 1, subdomain: 4798, rows: 6253
INFO[0001] abuseipdb: {"domain":1,"success":1,"found":1,"related":4797}
INFO[0001] sonarsearch/subdomains: {"domain":1,"success":1,"found":1,"related":1456}
```

## Format in output file
Unique Key: `root_domain` + `domain` + `method`

```json
{"root_domain":"<domain1>","domain":"<related_domain1>","method":"crawl/abuseipdb","type":"subdomain","extra_info":null}
{"root_domain":"<domain1>","domain":"<related_domain2>","method":"crawl/abuseipdb","type":"subdomain","extra_info":null}
{"root_domain":"<domain2>","domain":"<related_domain1>","method":"cert/crtsh","type":"related-domain","extra_info":null}
{"root_domain":"<domain2>","domain":"<related_domain2>","method":"api/sonarsearch/reverse","type":"related-domain","extra_info":{"ip":"111.222.111.222"}}
```
