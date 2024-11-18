package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"golang.org/x/net/http2"
)

var ()

const (
	staticResponse = `{
		"certificates": [
		  {
			"fingerprint_sha256": "c57a05cc6a2c63132b2607e6ceba75d472384055ccf77c179858f1f86f88c34f"
		  }
		]
	  }
`
)

type fingerprints struct {
	Fingerprint string `json:"fingerprint_sha256"`
}
type certResponse struct {
	Certificates []fingerprints `json:"certificates"`
}

func gethandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("/v1/certs/list/approved called\n")

	f := certResponse{
		Certificates: []fingerprints{
			{Fingerprint: "c57a05cc6a2c63132b2607e6ceba75d472384055ccf77c179858f1f86f88c34f"}},
	}

	jsonResponse, err := json.Marshal(f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Println(string(jsonResponse))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)
	//fmt.Fprint(w, staticResponse)
}

func hchandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("healthcheck called\n")
	fmt.Fprint(w, "ok")
}

func main() {

	router := mux.NewRouter()
	router.Methods(http.MethodGet).Path("/v1/certs/list/approved").HandlerFunc(gethandler)
	router.Methods(http.MethodGet).Path("/healthcheck").HandlerFunc(hchandler)

	clientCaCert, err := os.ReadFile("../ca_scratchpad/ca/root-ca.crt")
	if err != nil {
		panic(err)
	}
	clientCaCertPool := x509.NewCertPool()
	clientCaCertPool.AppendCertsFromPEM(clientCaCert)

	tlsConfig := &tls.Config{
		ClientAuth: tls.NoClientCert,
		// ClientCAs:  clientCaCertPool,
	}

	server := &http.Server{
		Addr:      ":18080",
		Handler:   router,
		TLSConfig: tlsConfig,
	}
	http2.ConfigureServer(server, &http2.Server{})
	fmt.Println("Starting Server..")
	err = server.ListenAndServeTLS("../ca_scratchpad/certs/certserver.crt", "../ca_scratchpad/certs/certserver.key")
	fmt.Printf("Unable to start Server %v", err)

}
