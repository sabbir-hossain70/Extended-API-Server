package server

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type GenericServer struct {
	cfg config
}

func NewGenericServer(cfg config) *GenericServer {
	return &GenericServer{cfg: cfg}
}

func (s *GenericServer) tlsconfig() *tls.Config {
	if s.cfg.CertFile == "" || s.cfg.KeyFile == "" {
		log.Fatalln("missing certfile, keyfile")
	}

	tlsconfig := &tls.Config{
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		ClientAuth: tls.VerifyClientCertIfGiven,
		NextProtos: []string{"h2", "http/1.1"},
	}
	caCertPool := x509.NewCertPool()
	for _, cacFile := range s.cfg.CACertFiles {
		caCert, err := ioutil.ReadFile(cacFile)
		if err != nil {
			log.Fatal(err)
		}
		caCertPool.AppendCertsFromPEM(caCert)
	}
	tlsconfig.ClientCAs = caCertPool
	tlsconfig.BuildNameToCertificate()
	return tlsconfig
}

func (s GenericServer) ListenAndServe(mux http.Handler) {
	log.Printf("Listening on %s\n", s.cfg.Address)
	srv := &http.Server{
		Addr:         s.cfg.Address,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		Handler:      mux,
	}
	srv.TLSConfig = s.tlsconfig()
	log.Fatalln(srv.ListenAndServeTLS(s.cfg.CertFile, s.cfg.KeyFile))
}
