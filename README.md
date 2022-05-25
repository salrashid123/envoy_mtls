### Envoy mTLS 

Sample configuration for HTTP and Network mTLS using envoy yaml

This demonstrates two types of mtls validation for the Downstream client (`client` -> `envoy_server`):

#### envoy.transport_sockets.tls


```bash
client ->  (mTLS) -> envoy  -> (TLS) -> upstream                       
```

#### envoy.filters.network.client_ssl_auth

This will validate `client` -> `envoy_server` over mTLS, using an external service as the source for valid certificate hashes.

```bash
                (auth_api_cluster)
                       ^
                       |
                     (TLS)
                       ^
                       |
client ->  (mTLS) -> envoy  -> (TLS) -> upstream                       
```

See:  [extensions.filters.network.client_ssl_auth.v3.ClientSSLAuth](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/network/client_ssl_auth/v3/client_ssl_auth.proto#extensions-filters-network-client-ssl-auth-v3-clientsslauth)


TBH...i'm not sure why you'd use `client_ssl_auth` versions since the external REST server it calls to validate a cert MUST send back **ALL** valid certificates....this is just poor.

---


### Configuration

1. Download envoy

** NOTE ** we are using the `envoy 1.21.0`
```
docker cp `docker create envoyproxy/envoy-dev:latest`:/usr/local/bin/envoy .

./envoy  version: 2e6db8378477a4a63740746c5bfeb264cd76bc34/1.21.0-dev/Clean/RELEASE/BoringSSL
```

This repo also uses its own CA.  If you want to use your own or make it from scratch, see [Create Root CA Key and cert](https://github.com/salrashid123/ca_scratchpad)


2. Run envoy_server

Each scenario has its own `yaml` file with just the components required.  Run the appropriate version to test with


---

### 1a.  envoy.transport_sockets.tls

* The client will establish a mTLS with envoy_server.
* Envoy Server will validate the presented client certificate against a list of approved CAs.
* Envoy will send down the OCSP stapled for the server
* curl with require OCSP stapled response and validate the cert

```bash
./envoy -c envoy_1.yaml -l debug
```


>> Note about `curl`:

Update `8/17/21`:
  The curl version >7.74 does not work anymore :( after [https://curl.se/docs/CVE-2020-8286.html](https://curl.se/docs/CVE-2020-8286.html).

  TBH, i think there is an issue with that fix itself [here](https://github.com/curl/curl/blob/e8cd39345e98cb543a07985effa365bb2ac1a1c1/lib/vtls/openssl.c#L1936-L1949) where it it does not check if the OCSP stapled response was signed by some dedicate CA even if its in the chain.

```bash
# $ curl --version
  # curl 7.74.0 (OpenSSL/1.1.1k zlib/1.2.11 

curl -v -H "host: http.domain.com"  \
   --resolve  http.domain.com:8081:127.0.0.1 \
   --cert certs/client.crt \
   --key certs/client.key  \
   --cacert certs/tls-ca-ocsp-chain.pem \
   --cert-status \
     https://http.domain.com:8081/get
# gives the error: curl: (91) Error computing OCSP ID
```

so as a workaround,we use a lower version to test with:

```bash
docker run     --net=host  \
    -v `pwd`/certs/:/certs curlimages/curl:7.73.0 -vvv \
    -H "host: http.domain.com"  \
    --resolve  http.domain.com:8081:127.0.0.1 \
     --cert /certs/client.crt --key /certs/client.key \
     --cacert /certs/tls-ca-chain.pem --cert-status  https://http.domain.com:8081/get
```


Anyway, lets take a careful look at `envoy_1.yaml`:

```yaml
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          require_client_certificate: true
          common_tls_context:
            tls_certificates:
            - certificate_chain:
                filename: certs/http_server.crt
              private_key:
                filename: certs/http_server.key
              ocsp_staple:
                filename: certs/http_server_ocsp_resp_valid.bin
            validation_context:
              only_verify_leaf_cert_crl: true
              trusted_ca:
                filename: certs/tls-ca-chain.pem                
              crl:
                filename: certs/tls-ca-valid.crl
```

When you run the client, you'll see the mtls and the server's cert was OCSP validated


```text
$ docker run     --net=host   \
    -v `pwd`/certs/:/certs curlimages/curl:7.73.0 -vvv     -H "host: http.domain.com"  \
    --resolve  http.domain.com:8081:127.0.0.1  \
    --cert /certs/client.crt --key /certs/client.key   \
    --cacert /certs/tls-ca-chain.pem --cert-status  https://http.domain.com:8081/get


* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*  CAfile: /certs/tls-ca-chain.pem
*  CApath: none
} [5 bytes data]
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
} [512 bytes data]
* TLSv1.3 (IN), TLS handshake, Server hello (2):
{ [122 bytes data]
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
{ [6 bytes data]
* TLSv1.3 (IN), TLS handshake, Request CERT (13):
{ [212 bytes data]
* TLSv1.3 (IN), TLS handshake, Certificate (11):
{ [2735 bytes data]
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
{ [264 bytes data]
* TLSv1.3 (IN), TLS handshake, Finished (20):
{ [52 bytes data]
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
} [1 bytes data]
* TLSv1.3 (OUT), TLS handshake, Certificate (11):
} [2120 bytes data]
* TLSv1.3 (OUT), TLS handshake, CERT verify (15):
} [264 bytes data]
* TLSv1.3 (OUT), TLS handshake, Finished (20):
} [52 bytes data]
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* ALPN, server did not agree to a protocol
* Server certificate:
*  subject: C=US; O=Google; OU=Enterprise; CN=http.domain.com
*  start date: May 25 11:43:01 2022 GMT
*  expire date: Feb 18 11:43:01 2027 GMT
*  subjectAltName: host "http.domain.com" matched cert's "http.domain.com"
*  issuer: C=US; O=Google; OU=Enterprise; CN=Enterprise Subordinate CA
*  SSL certificate verify ok.
* SSL certificate status: good (0)

```

A couple of things to note:

- `require_client_certificate: true`
  This bit is what this repo is about.

- `ocsp_staple`
  This specifies where to find the OCSP file to staple back to the client. See the `OCSP` section below about the format

- `crl`
  These specify the `CRL`s files for both the parent and subordinate CA. As mentioned above, the client cert is valid.  

- `only_verify_leaf_cert_crl: true`
  This checks the CRL for any CA thats part of chain.  In our case, we have a parent CA and a subordinate CA.  
  However, i have not been able to verify the full crl chain (i.,e make it work if its set to `false`)...this is a TODO.  If you do not specify a crl, you don't need to set this


### 1b. CRL revoke client certificate

Now test an envoy config where the client certificate is revoked.  We do this by setting the CRL filename to revoked version
(repoint to`filename: certs/tls-ca-revoked.crl`)

```yaml
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          require_client_certificate: true
          common_tls_context:
            tls_certificates:
            - certificate_chain:
                filename: certs/http_server.crt
              private_key:
                filename: certs/http_server.key
              ocsp_staple:
                filename: certs/http_server_ocsp_resp_valid.bin
            validation_context:
              only_verify_leaf_cert_crl: true
              trusted_ca:
                filename: certs/tls-ca-chain.pem
              crl:
                filename: certs/tls-ca-revoked.crl 
```

### 1b. send revoked OCSP Stapled server certificate

We can also verify the client's view of the server's cert by intentionally sending down a revoked OCSP stapled cert.  This is pretty contrived but shows how the client can validate the server's OCSP Stapled data

eg, (change to `tls_certificates.ocsp_staple.filename: certs/http_server_ocsp_resp_revoked.bin` and reset `crl.filename: certs/tls-ca-valid.crl`)

```yaml
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          require_client_certificate: true
          common_tls_context:
            tls_certificates:
            - certificate_chain:
                filename: certs/http_server.crt
              private_key:
                filename: certs/http_server.key
              ocsp_staple:
                filename: certs/http_server_ocsp_resp_revoked.bin
            validation_context:
              only_verify_leaf_cert_crl: true
              trusted_ca:
                filename: certs/tls-ca-chain.pem                
              crl:
                filename: certs/tls-ca-valid.crl
```

With this configuration, you will see the following error

```text
$ docker run     --net=host   \
    -v `pwd`/certs/:/certs curlimages/curl:7.73.0 -vvv  \
    -H "host: http.domain.com"      --resolve  http.domain.com:8081:127.0.0.1  \
    --cert /certs/client.crt --key /certs/client.key  \
    --cacert /certs/tls-ca-chain.pem --cert-status  https://http.domain.com:8081/get


 ALPN, server did not agree to a protocol
* Server certificate:
*  subject: C=US; O=Google; OU=Enterprise; CN=http.domain.com
*  start date: May 25 11:43:01 2022 GMT
*  expire date: Feb 18 11:43:01 2027 GMT
*  subjectAltName: host "http.domain.com" matched cert's "http.domain.com"
*  issuer: C=US; O=Google; OU=Enterprise; CN=Enterprise Subordinate CA
*  SSL certificate verify ok.
* SSL certificate status: revoked (1)
* SSL certificate revocation reason: (UNKNOWN) (-1)

```

### 1c. Verify client with SPKI

  You can also opt to very the client cert presented using the hash value 

* [verify_certificate_spki](https://cloudnative.to/envoy/api-v2/api/v2/auth/common.proto.html)

```
An optional list of base64-encoded SHA-256 hashes. If specified, Envoy will verify that the SHA-256 of the DER-encoded Subject Public Key Information (SPKI) of the presented certificate matches one of the specified values.
```

For our client certificate, its

```bash
$ openssl x509 -in certs/client.crt -noout -pubkey  | openssl pkey -pubin -outform DER  | openssl dgst -sha256 -binary  | openssl enc -base64
      0FDpHG3vRLuRng8gkBA9UB0pbr3MUQ48EA16LqjsEzY=
```

so the configuration is

```yaml
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          require_client_certificate: true
          common_tls_context:
            tls_certificates:
            - certificate_chain:
                filename: certs/http_server.crt
              private_key:
                filename: certs/http_server.key
              ocsp_staple:
                filename: certs/http_server_ocsp_resp_valid.bin
            validation_context:             
              verify_certificate_spki:
              - "0FDpHG3vRLuRng8gkBA9UB0pbr3MUQ48EA16LqjsEzY=" 
```

### envoy.filters.network.client_ssl_auth

In this section we will use the network TLS filter  `envoy.filters.network.client_ssl_auth`

[extensions.filters.network.client_ssl_auth.v3.ClientSSLAuth](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/network/client_ssl_auth/v3/client_ssl_auth.proto#extensions-filters-network-client-ssl-auth-v3-clientsslauth)

To use this, we will need an external server which accepts the TLS client hash, validates it and then return a decision if its acceptable or not

So run our external server

```
$ go run src/server/main.go
```

The server responds back to REST calls

```bash
$ curl -s --cacert certs/tls-ca.crt -H "host: certserver.domain.com" \
  --resolve certserver.domain.com:18080:127.0.0.1 https://certserver.domain.com:18080/v1/certs/list/approved | jq '.'
{
  "certificates": [
    {
      "fingerprint_sha256": "f1e93b2401a998ae419bdcb150c3b23e962d3d7faff9d744c99d9d18678a239e"
    }
  ]
}
```

Note that the fingerprint is our client certificate
```
$ openssl x509 -in certs/client.crt -outform DER | openssl dgst -sha256 | cut -d" " -f2
  f1e93b2401a998ae419bdcb150c3b23e962d3d7faff9d744c99d9d18678a239e
```

what this means is that the external server will ONLY trust one certificate


>> as a side now..i have no idea how this design is scalable...i mean, the external server must return ALL the certificates that are valid _as a list_

This is a really poor design ...I suspect this mode isn't used...

Anyway, lets run the server


```
./envoy -c envoy_2.yaml -l debug
```

- `envoy_2.yaml`,

Note the filter setting here points to an external cluster `auth_api_cluster`

```yaml
    filter_chains:
    - filters:
      - name: envoy.filters.network.client_ssl_auth
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.client_ssl_auth.v3.ClientSSLAuth
          stat_prefix: client_authn
          auth_api_cluster: cert_service
          refresh_delay: 5s  
```

The `cert_server` is the go app server we're running.

On startup, envoy perform healthcheck AND periodically asks the external server for list of valid certs...

again, i have no idea how this is scales...

```yaml
node:
  cluster: service_greeter
  id: test-id

static_resources:
  listeners:
  - name: listener_0
    address:
      socket_address: { address: 0.0.0.0, port_value: 8081 }
    filter_chains:
    - filters:
      - name: envoy.filters.network.client_ssl_auth
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.client_ssl_auth.v3.ClientSSLAuth
          stat_prefix: client_authn
          auth_api_cluster: cert_service
          refresh_delay: 5s    
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          codec_type: AUTO
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - match:
                  prefix: "/"
                route:
                  cluster: service_httpbin
            request_headers_to_add:
            - header:
                key: downstream_peer_fingerprint
                value: "%DOWNSTREAM_PEER_FINGERPRINT_256%"
          http_filters:
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router          
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          require_client_certificate: true
          common_tls_context:
            tls_certificates:
            - certificate_chain:
                filename: certs/http_server.crt
              private_key:
                filename: certs/http_server.key
              ocsp_staple:
                filename: certs/http_server_ocsp_resp_valid.bin
            validation_context:
              only_verify_leaf_cert_crl: true
              trusted_ca:
                filename: certs/tls-ca-chain.pem                
  clusters:
  - name: service_httpbin
    connect_timeout: 0.25s
    type: strict_dns
    lb_policy: round_robin
    load_assignment:
      cluster_name: service_httpbin
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: httpbin.org
                port_value: 443
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
  - name: cert_service
    connect_timeout: 0.25s
    type: strict_dns
    lb_policy: round_robin
    load_assignment:
      cluster_name: cert_service
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: 18080
    health_checks:
      - timeout: 1s
        interval: 2s
        unhealthy_threshold: 3
        healthy_threshold: 1
        http_health_check:
          path: /healthcheck                
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        common_tls_context:
          validation_context:
            match_subject_alt_names:
              exact: "certserver.domain.com"
            trusted_ca:
              filename: "certs/tls-ca-chain.pem"
```

if you want to see it succeed,  just run  envoy with the `envoy_2.yaml` config, the remote server `src/server/main.go` and a client that sends over the cert:

```bash
 docker run     --net=host       -v `pwd`/certs/:/certs curlimages/curl:7.73.0 -vvv      -H "host: http.domain.com"      --resolve  http.domain.com:8081:127.0.0.1      --cert /certs/client.crt --key /certs/client.key      --cacert /certs/tls-ca-chain.pem --cert-status  https://http.domain.com:8081/get
```

If you want to see it fail, stop envoy, stop the server, edit the main.go and change any hex field that is expected/approved:

eg, change any value here
```golang
const (
	staticResponse = `{
		"certificates": [
		  {
			"fingerprint_sha256": "f1e93b2401a998ae419bdcb150c3b23e962d3d7faff9d744c99d9d18678a239e"
		  }
		]
	  }
`
)
```

then restart envoy, restart the server and run the curl command again...you'll see it fail
---

Thats about it...dont' use `envoy.extensions.filters.network.client_ssl_auth.v3.ClientSSLAuth`  for mtls

---

##### Background


### CA Structure

First some background on the certificate specifications we will use in these example (you can skip these and come back later)

- `root-ca.crt`

This is the root CA:

```bash
$ openssl x509 -in certs/root-ca.crt -noout -text

    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number: 1 (0x1)
            Signature Algorithm: sha256WithRSAEncryption
            Issuer: C = US, O = Google, OU = Enterprise, CN = Enterprise Root CA
            Validity
                Not Before: May 25 11:37:48 2022 GMT
                Not After : May 24 11:37:48 2032 GMT
            Subject: C = US, O = Google, OU = Enterprise, CN = Enterprise Root CA
            X509v3 extensions:
                X509v3 Key Usage: critical
                    Certificate Sign, CRL Sign
                X509v3 Basic Constraints: critical
                    CA:TRUE
                X509v3 Subject Key Identifier: 
                    A9:DE:EE:20:0B:8E:F3:9D:C2:30:BE:20:15:EE:FA:67:BB:24:6B:7F
                X509v3 Authority Key Identifier: 
                    keyid:A9:DE:EE:20:0B:8E:F3:9D:C2:30:BE:20:15:EE:FA:67:BB:24:6B:7F

  
```

This CA has a CRL as well but we have not expired anything:

```bash

$ openssl crl -inform PEM -text -noout -in certs/root-ca.crl 
      Certificate Revocation List (CRL):
              Version 2 (0x1)
              Signature Algorithm: sha256WithRSAEncryption
              Issuer: C = US, O = Google, OU = Enterprise, CN = Enterprise Root CA
              Last Update: May 25 11:38:47 2022 GMT
              Next Update: Sep  6 11:38:47 2025 GMT
              CRL extensions:
                  X509v3 Authority Key Identifier: 
                      keyid:A9:DE:EE:20:0B:8E:F3:9D:C2:30:BE:20:15:EE:FA:67:BB:24:6B:7F

                  Authority Information Access: 
                      CA Issuers - URI:http://pki.esodemoapp2.com/ca/root-ca.cer

                  X509v3 CRL Number: 
                      1
      No Revoked Certificates.
```

- `tls-ca.crt`

This is the subordinate CA that issues the TLS client and server certificates:

```bash
openssl x509 -in certs/tls-ca.crt -noout -text
    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number: 2 (0x2)
            Signature Algorithm: sha256WithRSAEncryption
            Issuer: C = US, O = Google, OU = Enterprise, CN = Enterprise Root CA
            Validity
                Not Before: May 25 11:39:20 2022 GMT
                Not After : May 24 11:39:20 2032 GMT
            Subject: C = US, O = Google, OU = Enterprise, CN = Enterprise Subordinate CA
            X509v3 extensions:
                X509v3 Key Usage: critical
                    Certificate Sign, CRL Sign
                X509v3 Basic Constraints: critical
                    CA:TRUE, pathlen:0
                X509v3 Subject Key Identifier: 
                    65:11:BD:CE:06:7C:D4:7C:74:7F:34:3F:F4:83:4A:68:7D:F9:E0:76
                X509v3 Authority Key Identifier: 
                    keyid:A9:DE:EE:20:0B:8E:F3:9D:C2:30:BE:20:15:EE:FA:67:BB:24:6B:7F 
```

Note that we have two CRLs here: one with a revoked cert and one without.  We will later use these separately to test with

This is the one that doens't have certs revoked

```bash
$ openssl crl -inform PEM -text -noout -in certs/tls-ca-valid.crl 

    Certificate Revocation List (CRL):
            Version 2 (0x1)
            Signature Algorithm: sha256WithRSAEncryption
            Issuer: C = US, O = Google, OU = Enterprise, CN = Enterprise Subordinate CA
            Last Update: May 25 12:46:16 2022 GMT
            Next Update: Sep  6 12:46:16 2025 GMT
            CRL extensions:
                X509v3 Authority Key Identifier: 
                    keyid:65:11:BD:CE:06:7C:D4:7C:74:7F:34:3F:F4:83:4A:68:7D:F9:E0:76

                Authority Information Access: 
                    CA Issuers - URI:http://pki.esodemoapp2.com/ca/tls-ca.cer

                X509v3 CRL Number: 
                    3
    No Revoked Certificates.

```

and

```bash
$ openssl crl -inform PEM -text -noout -in certs/tls-ca-revoked.crl 
      Certificate Revocation List (CRL):
              Version 2 (0x1)
              Signature Algorithm: sha256WithRSAEncryption
              Issuer: C = US, O = Google, OU = Enterprise, CN = Enterprise Root CA
              Last Update: May 25 10:59:04 2022 GMT
              Next Update: Feb 18 10:59:04 2025 GMT
              CRL extensions:
                  X509v3 Authority Key Identifier: 
                      keyid:49:A6:84:17:0A:2A:EE:75:56:FD:BA:57:B1:B4:DD:B5:B6:4D:BA:DF
                  X509v3 CRL Number: 
                      3
      Revoked Certificates:
          Serial Number: 02
              Revocation Date: May 25 10:58:04 2022 GMT

```

Note the Serial Number (`02`), this is the serial number for the revoked TLS Sub CA (eg tls-ca.crt has `Serial Number: 2 (0x2)` as signed by the root-ca)


- `http_server.crt`

This is the certificate the envoy server uses

```bash
$ openssl x509 -in certs/http_server.crt -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 2 (0x2)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, O = Google, OU = Enterprise, CN = Enterprise Subordinate CA
        Validity
            Not Before: May 25 11:43:01 2022 GMT
            Not After : Feb 18 11:43:01 2027 GMT
        Subject: C = US, O = Google, OU = Enterprise, CN = http.domain.com
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Subject Key Identifier: 
                8B:8A:11:49:03:F9:F5:16:E3:BF:15:82:2D:60:0F:C0:9D:46:E8:7B
            X509v3 Authority Key Identifier: 
                keyid:65:11:BD:CE:06:7C:D4:7C:74:7F:34:3F:F4:83:4A:68:7D:F9:E0:76
            X509v3 Subject Alternative Name: 
                DNS:http.domain.com


```

Note the SAN Value

- `client.crt` 

This is the certificate the client will present to the envoy server

```bash
$ openssl x509 -in certs/client.crt -noout -text 
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 4 (0x4)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, O = Google, OU = Enterprise, CN = Enterprise Subordinate CA
        Validity
            Not Before: May 25 11:44:41 2022 GMT
            Not After : Feb 18 11:44:41 2027 GMT
        Subject: C = US, O = Google, OU = Enterprise, CN = client@domain.com
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication


```

Note the SAN value as well as the serial number (` Serial Number: 4 (0x4)`) which will be used for CRL based validation


Also, we will generate the digest value (we will use this later to indicate valid certificates):

```bash
$ openssl x509 -in certs/client.crt -outform DER | openssl dgst -sha256 | cut -d" " -f2
  f1e93b2401a998ae419bdcb150c3b23e962d3d7faff9d744c99d9d18678a239e

$ openssl x509 -in certs/client.crt -noout -pubkey  | openssl pkey -pubin -outform DER  | openssl dgst -sha256 -binary  | openssl enc -base64
  0FDpHG3vRLuRng8gkBA9UB0pbr3MUQ48EA16LqjsEzY=
```


The following just some background commands for CRL's and OCSP

#### CRL

Note the `Revoked Certificates` list where the serial number is listed

```bash
$ openssl crl -inform PEM -text -noout -in certs/tls-ca-evoked.crl 
      Certificate Revocation List (CRL):
              Version 2 (0x1)
              Signature Algorithm: sha256WithRSAEncryption
              Issuer: C = US, O = Google, OU = Enterprise, CN = Enterprise Subordinate CA
              Last Update: May 25 12:13:28 2022 GMT
              Next Update: Sep  6 12:13:28 2025 GMT
              CRL extensions:
                  X509v3 Authority Key Identifier: 
                      keyid:65:11:BD:CE:06:7C:D4:7C:74:7F:34:3F:F4:83:4A:68:7D:F9:E0:76

                  Authority Information Access: 
                      CA Issuers - URI:http://pki.esodemoapp2.com/ca/tls-ca.cer

                  X509v3 CRL Number: 
                      3
      Revoked Certificates:
          Serial Number: 04      <<<<<<<<<<<<<<<
              Revocation Date: May 25 12:13:00 2022 GMT

```

##### OCSP


Use openssl to test the OCSP Responder:

- Valid server certificate:
```bash
$ cd certs/
$ openssl ocsp -index db_valid/tls-ca.db -port 9999 -rsigner ocsp.crt -rkey ocsp.key -CA tls-ca.crt -text -ndays 1500

$ openssl ocsp -CA tls-ca.crt -CAfile tls-ca-ocsp-chain.pem -issuer tls-ca.crt  -cert http_server.crt -url http://localhost:9999 -resp_text

$ openssl ocsp -CA tls-ca.crt -CAfile tls-ca-ocsp-chain.pem -issuer tls-ca.crt  -cert http_server.crt -url http://localhost:9999 -respout http_server_ocsp_resp_valid.bin

    Response verify OK
    http_server.crt: good
      This Update: May 25 12:49:51 2022 GMT
      Next Update: Jul  3 12:49:51 2026 GMT

```

or with openssl client/server

```
$ openssl s_server \
  -status_file http_server_ocsp_resp_valid.bin \
  -cert http_server.crt -key http_server.key \
  -port 8081 -CAfile tls-ca-ocsp-chain.pem \
  -verify_return_error -Verify 1

$ openssl s_client \
  -connect localhost:8081 \
  -servername http.domain.com \
  -CAfile tls-ca-chain.pem \
  -cert client.crt \
  -key client.key -tls1_3 -tlsextdebug -status --verify 1
```


- Revoked Server certificate

```bash
cd certs/
openssl ocsp -index db_revoked/tls-ca.db -port 9999 -rsigner ocsp.crt -rkey ocsp.key -CA tls-ca.crt -text -ndays 500

openssl ocsp -CA tls-ca.crt -CAfile tls-ca-ocsp-chain.pem -issuer tls-ca.crt  -cert http_server.crt -url http://localhost:9999 -resp_text

$ openssl ocsp -CA tls-ca.crt -CAfile tls-ca-ocsp-chain.pem -issuer tls-ca.crt  -cert http_server.crt -url http://localhost:9999 -respout http_server_ocsp_resp_revoked.bin
    Response verify OK
    http_server.crt: revoked
      This Update: May 25 12:50:25 2022 GMT
      Next Update: Oct  7 12:50:25 2023 GMT
      Revocation Time: May 25 12:18:16 2022 GMT

```


### References

- [Envoy WASM and LUA filters for Certificate Bound Tokens](https://github.com/salrashid123/envoy_cert_bound_token)
- [Envoy control plane "hello world"](https://github.com/salrashid123/envoy_control)
- [Envoy mTLS and JWT Auth with RBAC](https://github.com/salrashid123/envoy_rbac)
- [Envoy, Nginx, Apache HTTP Structured Logging with Google Cloud Logging](https://github.com/salrashid123/gcp_envoy_nginx_apache_structured_logs)
- [Envoy http/tcp Parser Plugin for Fluentd](https://github.com/salrashid123/fluent-plugin-envoy-parser)
- [Envoy EDS "hello world"](https://github.com/salrashid123/envoy_discovery)
- [Envoy Global rate limiting helloworld](https://github.com/salrashid123/envoy_ratelimit)
- [Envoy External Authorization server (envoy.ext_authz) HelloWorld](https://github.com/salrashid123/envoy_external_authz)
- [Envoy for Google Cloud Identity Aware Proxy](https://github.com/salrashid123/envoy_iap)
- [Envoy mTLS and JWT Auth with RBAC](https://github.com/salrashid123/envoy_rbac)

- [Create Root CA Key and cert](https://github.com/salrashid123/ca_scratchpad)

---
