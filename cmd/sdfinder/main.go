package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"
	"strings"

	"github.com/shlin168/sdfinder"
	"github.com/shlin168/sdfinder/sources"
	"github.com/sirupsen/logrus"
)

func main() {
	fset := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	srcPath := fset.String("src", "", "source file with domain list. domains should be seperated by '\n'")
	domains := fset.String("d", "", "domains to get subdomains if not given by '-src'. sep by ','")
	cfgPath := fset.String("cfg", "", "config file path for sources to define custom qps, retries, .... use default config if not given")
	resolveIP := fset.Bool("ip", false, "whether resolve ip for given domain to query API that serve IP or not")
	outPath := fset.String("out", "", "path to write the result in json line. Each line represents one related domain found by one source")
	queriersStr := fset.String("q", "", "limit to given sources, sep by ','. Default using all sources")
	worker := fset.Int("worker", sources.DefaultWorker, "concurrency for each API if config is not given")
	fset.Parse(os.Args[1:])

	if len(*srcPath)+len(*domains) == 0 {
		log.Fatal("domains should be either given by -src=<filepath> or -d=<domain>")
	}
	if len(*srcPath) > 0 && len(*domains) > 0 {
		log.Fatal("domains should be either given by -src=<filepath> or -d=<domain>, can not provide both")
	}
	if *outPath == "" {
		log.Fatal("out file path should be given by -out")
	}
	if len(*cfgPath) > 0 {
		if len(*queriersStr) > 0 {
			log.Fatal("-q is skipped when -cfg=<configpath> is given")
		}
		if *worker > 0 {
			log.Println("-worker is skipped when -cfg=<configpath> is given")
		}
	} else {
		if *worker <= 0 {
			log.Fatal("workers should > 0")
		}
	}

	// read from config, or using default
	var cfg *sources.Config
	if *cfgPath == "" {
		logrus.Info(`config file not given, using default config for sources`)
		var enabledSDFinders []string
		for _, qs := range strings.Split(*queriersStr, ",") {
			if len(qs) > 0 {
				enabledSDFinders = append(enabledSDFinders, qs)
			}
		}
		// if enabledSDFinders is empty, default enabled all available subdomain finders
		// which is filled by sources.GenDefaultConfig()
		cfg = sources.GenDefaultConfig(enabledSDFinders, *worker)
	} else {
		logrus.Infof(`read config file %s for custom config`, *cfgPath)
		var err error
		// read config and enabled subdomain finders defined in config file
		cfg, err = sources.ReadConfigFromFile(*cfgPath)
		if err != nil {
			log.Fatalln(err)
		}
	}
	logger := logrus.New()
	lf := logrus.Fields{
		"out":        *outPath,
		"resolve-ip": *resolveIP,
	}
	if len(*cfgPath) > 0 {
		lf["cfg-path"] = *cfgPath
	} else {
		lf["worker"] = *worker
		if len(*queriersStr) > 0 {
			lf["queriers"] = *queriersStr
		}
	}
	if len(*srcPath) > 0 {
		lf["src-path"] = *srcPath
	}
	if len(*domains) > 0 {
		lf["domains"] = *domains
	}
	logger.WithFields(lf).Info("flag")

	// read input from file(-src=<file path>) or command line(-d=<domain1>,<domain2>)
	var reader sdfinder.Reader
	if len(*srcPath) > 0 {
		srcFile, err := os.Open(*srcPath)
		if err != nil {
			log.Fatalf("read customer domain error: %v", err)
		}
		defer srcFile.Close()
		reader = sdfinder.NewFileReader(srcFile)
	} else if len(*domains) > 0 {
		reader = sdfinder.NewStrReader(bufio.NewReader(strings.NewReader(*domains)), ',')
	}

	// start subdomains queriers to handle incoming domains (and ips)
	subdomainFinders, err := sources.NewExecutorWithConfig(cfg)
	if err != nil {
		log.Fatalf("init err: %v", err)
	}
	subdomainFinders.StartWorkers(context.Background())

	inChan := make(chan sources.Query)
	outChan := subdomainFinders.FlattenOutput(
		subdomainFinders.SendToQueriersAndAggr(context.Background(), inChan),
	)
	go func() {
		if err := sdfinder.Read(reader, func(domain string) {
			if len(domain) == 0 {
				return
			}
			var queries []sources.Query
			query := sources.Query{Domain: domain}
			if *resolveIP {
				ips, _ := net.LookupIP(domain)
				for _, ip := range ips {
					if ipv4 := ip.To4(); ipv4 != nil {
						query.IP = ipv4.String()
						queries = append(queries, query)
					}
				}
			} else {
				queries = append(queries, query)
			}
			for _, qItem := range queries {
				inChan <- qItem
			}
		}, func() {
			close(inChan)
		}); err != nil {
			log.Fatal(err)
		}
	}()

	// open file to write the result
	var outFile *os.File
	outFile, err = os.OpenFile(*outPath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("open file error: %v", err)
	}
	defer outFile.Close()

	for record := range outChan {
		out, err := json.Marshal(record)
		if err != nil {
			logger.WithField("domain", record.Domain).WithError(err).Error("marshal")
			continue
		}
		if _, err = outFile.Write(append(out, []byte("\n")...)); err != nil {
			logger.WithField("domain", record.Domain).WithError(err).Error("write file")
		}
	}

	// collect statistic information and print
	subdomainFinders.CollectStat()
	logger.Infof("[unique] domain: %d, subdomain: %d, rows: %d\n",
		subdomainFinders.Stat.DomainsCnt,
		subdomainFinders.Stat.SubDomainsCnt,
		subdomainFinders.Stat.TotalOutputRow,
	)
	for _, item := range subdomainFinders.Querier {
		queryStat, err := json.Marshal(item.Client.GetStat())
		if err != nil {
			logger.WithField("name", item.Name).WithError(err).Warn("decode stat")
			continue
		}
		logger.Infof("%s: %s\n", item.Name, string(queryStat))
	}
}
