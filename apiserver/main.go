package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/sabbir-hossain70/Extended-API-Server/lib/certstore"
	"github.com/sabbir-hossain70/Extended-API-Server/lib/server"
	"github.com/spf13/afero"
	"io"
	"k8s.io/client-go/util/cert"
	"log"
	"net"
	"net/http"
	"time"
)

func main() {
	var proxy = false
	flag.BoolVar(&proxy, "send-proxy-request", proxy, "Forward request to database-extended-api-server")
	flag.Parse()

	fs := afero.NewOsFs()
	store, err := certstore.NewCertStore(fs, certstore.CertDir)
	if err != nil {
		log.Fatal(err)
	}
	err = store.InitCA("apiserver")
	if err != nil {
		log.Fatal(err)
	}
	serverCert, serverKey, err := store.NewServerCertPair(cert.AltNames{
		IPs: []net.IP{net.ParseIP("127.0.0.1")},
	})

	if err != nil {
		log.Fatal(err)
	}

	err = store.Write("tls", serverCert, serverKey)
	if err != nil {
		log.Fatal(err)
	}
	clientCert, clientKey, err := store.NewClientCertPair(cert.AltNames{
		DNSNames: []string{"sabbir"},
	})
	if err != nil {
		log.Fatal(err)
	}
	err = store.Write("sabbir", clientCert, clientKey)
	if err != nil {
		log.Fatal(err)
	}

	rhStore, err := certstore.NewCertStore(fs, certstore.CertDir)
	if err != nil {
		log.Fatal(err)
	}
	err = rhStore.InitCA("requestheader")
	if err != nil {
		log.Fatal(err)
	}

	rhClientCert, rhClientKey, err := rhStore.NewClientCertPair(cert.AltNames{
		DNSNames: []string{"apiserver"},
	})

	if err != nil {
		log.Fatal(err)
	}

	err = rhStore.Write("apiserver", rhClientCert, rhClientKey)
	if err != nil {
		log.Fatal(err)
	}

	rhCert, err := tls.LoadX509KeyPair(rhStore.CertFile("apiserver"), rhStore.KeyFile("apiserver"))
	if err != nil {
		log.Fatal(err)
	}
	easCACertPool := x509.NewCertPool()
	if proxy {
		easStore, err := certstore.NewCertStore(fs, certstore.CertDir)
		if err != nil {
			log.Fatal(err)
		}
		err = easStore.LoadCA("database")
		if err != nil {
			log.Fatal(err)
		}
		easCACertPool.AppendCertsFromPEM(easStore.CACertBytes())
	}

	cfg := server.Config{
		Address: "127.0.0.1:8443",
		CACertFiles: []string{
			store.CertFile("ca"),
		},
		CertFile: store.CertFile("tls"),
		KeyFile:  store.KeyFile("tls"),
	}

	srv := server.NewGenericServer(cfg)
	r := mux.NewRouter()
	r.HandleFunc("/core/{resource}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Resource -> %v\n", vars["resource"])
	})

	if proxy {
		r.HandleFunc("/database/{resource}", func(w http.ResponseWriter, r *http.Request) {
			tr := &http.Transport{
				MaxConnsPerHost: 10,
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{rhCert},
					RootCAs:      easCACertPool,
				},
			}
			client := &http.Client{
				Transport: tr,
				Timeout:   time.Duration(20 * time.Second),
			}
			u := *r.URL
			u.Scheme = "https"
			u.Host = "127.0.0.2:8443"
			fmt.Println("Forwarding request to " + u.String())
			req, _ := http.NewRequest(r.Method, u.String(), nil)
			if len(r.TLS.PeerCertificates) > 0 {
				req.Header.Set("X-Remote-User", r.TLS.PeerCertificates[0].Subject.CommonName)
			}
			resp, err := client.Do(req)

			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "Error -> %v\n", err)
				return
			}
			defer resp.Body.Close()
			w.WriteHeader(http.StatusOK)
			io.Copy(w, resp.Body)

		})
	}
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(w, "OK....")
	})
	srv.ListenAndServe(r)
}
