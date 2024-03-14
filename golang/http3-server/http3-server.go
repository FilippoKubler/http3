package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"bytes"
	"io"

	_ "net/http/pprof"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	//"github.com/quic-go/quic-go/internal/testdata"
	"github.com/quic-go/quic-go/qlog"
)

type binds []string

func (b binds) String() string {
	return strings.Join(b, ",")
}

func (b *binds) Set(v string) error {
	*b = strings.Split(v, ",")
	return nil
}

// Size is needed by the /demo/upload handler to determine the size of the uploaded file
type Size interface {
	Size() int64
}



func setupHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		
		log.Printf("**************************************************************************\n")
		
		reqDump, err := httputil.DumpRequest(req, true)
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("Got Request from: %s\n%s", req.RemoteAddr, string(reqDump))
		
		log.Printf("**************************************************************************\n\n")

		method 			:= req.Method
		addr 			:= "http://127.0.0.1:31112" + req.RequestURI
		reqBody 		:= req.Body
		
		var content_type 	string
		if strings.Contains(addr, "figlet") {
			content_type 	= "application/x-www-form-urlencoded"
		} else {
			content_type 	= "application/json; charset=UTF-8"
		}

		log.Printf("Redirect %s Request to: %s . . .\n\n", method, addr)

		// Forward request to correct function
		switch method {

			case "GET":
				res, err := http.Get(addr)
				if err != nil {
					log.Printf("Error making http request: %s\n", err)
				}
				if res.StatusCode != 200 {
					log.Printf("Error - Status Code: %d\n", res.StatusCode)
				} else {
					respDump, err := httputil.DumpResponse(res, true)
					if err != nil {
						log.Fatal(err)
					}
					log.Printf("Got response from %s: \n%s\n", addr, string(respDump))

					w.WriteHeader(200)
				}

			case "POST":
				res, err := http.Post(addr, content_type, reqBody)
				if err != nil {
					log.Printf("Error making http request: %s\n", err)
				}
				if res.StatusCode != 200 {
					log.Printf("Error - Status Code: %d\n", res.StatusCode)
				} else {
					respDump, err := httputil.DumpResponse(res, true)
					if err != nil {
						log.Fatal(err)
					}
					log.Printf("Got response from %s: \n%s\n", addr, string(respDump))

					resBody := &bytes.Buffer{}
					_, err = io.Copy(resBody, res.Body)
					if err != nil {
						log.Fatal(err)
					}
					w.Write(resBody.Bytes())
				}

			default:
				log.Printf("")
		}

		log.Printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n\n\n\n")
	})
	
	return mux
}





func main() {
	// defer profile.Start().Stop()
	// go func() {
	// 	log.Println(http.ListenAndServe("0.0.0.0:6060", nil))
	// }()
	// runtime.SetBlockProfileRate(1)
	
	log.Printf("Starting Server HTTP/3 - Listening on 0.0.0.0:30443\n\n")

	bs := binds{"0.0.0.0:30443"}

	handler := setupHandler()

	var wg sync.WaitGroup
	wg.Add(len(bs))
	
	go func() {
		// var err error
		
		server := &http3.Server{
			Handler: 	handler,
			Addr:    	bs[0],
			QuicConfig: &quic.Config{
				Tracer: 	qlog.DefaultTracer,
			},
		}

		listenUntilShutdown(server)

		wg.Done()
	}()

	wg.Wait()
}


func listenUntilShutdown(s *http3.Server) {

	idleConnsClosed := make(chan struct{})

	// Run the HTTP server in a separate go-routine.
	go func() {

		var certFile, keyFile string
		
		certFile = "./certs/cert.pem"
		keyFile = "./certs/priv.key"

		if err := s.ListenAndServeTLS(certFile, keyFile); err != http.ErrServerClosed {
			log.Printf("Error ListenAndServe: %v", err)
			close(idleConnsClosed)
		}
	}()

	<-idleConnsClosed
}