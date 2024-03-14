package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io"
	"net/http"
	"net/http/httputil"
	"log"
	"os"
	"sync"
	"strings"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	//"github.com/quic-go/quic-go/internal/testdata"
	"github.com/quic-go/quic-go/qlog"
)

func main() {
	
	keyLogFile := flag.String("keylog", "", "key log file")
	insecure := flag.Bool("insecure", false, "skip certificate verification")
	method := flag.String("method", "GET", "specify request method")
	payload := flag.String("payload", "", "specify request payload")
	flag.Parse()
	urls := flag.Args()
	
	// log.Printf("%t - %s - %t\n", *quiet, *keyLogFile, *insecure)
	// log.Printf("Flags: %s\n", flag.Args())
	
	log.Printf("Start HTTP3 Client . . .\n\n")
	
	var keyLog io.Writer
	if len(*keyLogFile) > 0 {
		f, err := os.OpenFile(*keyLogFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		keyLog = f
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}
	// pool := x509.NewCertPool()
	AddRootCA(pool)

	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: *insecure,
			KeyLogWriter:       keyLog,
		},
		QuicConfig: &quic.Config{
			Tracer: qlog.DefaultTracer,
		},
	}
	defer roundTripper.Close()
	hclient := &http.Client{
		Transport: roundTripper,
	}

	var wg sync.WaitGroup
	wg.Add(len(urls))
	for _, addr := range urls {

		switch *method {

			case "GET":
				log.Printf("GET %s", addr)
				go func(addr string) {

					res, err := hclient.Get(addr)
					if err != nil {
						log.Fatal(err)
					}

					log.Printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n")

					respDump, err := httputil.DumpResponse(res, true)
					if err != nil {
						log.Fatal(err)
					}
					log.Printf("Got response from %s: \n%s\n", addr, string(respDump))

					log.Printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n")

					wg.Done()
				}(addr)

			case "POST":
				log.Printf("POST %s", addr)

				content_type 	:= "text/plain; charset=UTF-8"
				reqBody 		:= strings.NewReader(*payload)

				go func(addr string) {

					res, err := hclient.Post(addr, content_type, reqBody)
					if err != nil {
						log.Fatal(err)
					}

					log.Printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n")

					respDump, err := httputil.DumpResponse(res, true)
					if err != nil {
						log.Fatal(err)
					}
					log.Printf("Got response from %s: \n%s\n", addr, string(respDump))

					log.Printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n")

					wg.Done()
				}(addr)
				
			default:
				log.Printf("")
		}

	}
	wg.Wait()
}


func AddRootCA(certPool *x509.CertPool) {
	caCertRaw, err := os.ReadFile("certs/cert.pem")
	if err != nil {
		panic(err)
	}
	if ok := certPool.AppendCertsFromPEM(caCertRaw); !ok {
		panic("Could not add root ceritificate to pool.")
	}
}