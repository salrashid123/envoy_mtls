package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"
	"golang.org/x/net/http2"
)

var ()

const (
	staticResponse = `{
		"certificates": [
		  {
			"fingerprint_sha256": "492d412c90b7d1747f02583d03dbf52e009fde113dd454bd5de572bde6595efc"
		  }
		]
	  }
`
)

func gethandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("/v1/certs/list/approved called\n")
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, staticResponse)
}

func hchandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "ok")
}

func main() {

	router := mux.NewRouter()
	router.Methods(http.MethodGet).Path("/v1/certs/list/approved").HandlerFunc(gethandler)
	router.Methods(http.MethodGet).Path("/healthcheck").HandlerFunc(hchandler)

	clientCaCert, err := ioutil.ReadFile("certs/tls-ca.crt")
	clientCaCertPool := x509.NewCertPool()
	clientCaCertPool.AppendCertsFromPEM(clientCaCert)

	tlsConfig := &tls.Config{
		ClientAuth: tls.NoClientCert,
		// ClientCAs:  clientCaCertPool,
	}

	var server *http.Server
	server = &http.Server{
		Addr:      ":18080",
		Handler:   router,
		TLSConfig: tlsConfig,
	}
	http2.ConfigureServer(server, &http2.Server{})
	fmt.Println("Starting Server..")
	err = server.ListenAndServeTLS("certs/certserver.crt", "certs/certserver.key")
	fmt.Printf("Unable to start Server %v", err)

}
