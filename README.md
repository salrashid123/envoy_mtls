### Envoy mTLS 

Sample configuration for HTTP and Network mTLS using envoy yaml

Sample demonstrates:

  * 1. `client` -> `envoy_server` over mTLS, require OCSP staple
  * 2. `envoy_server` HTTP filter validates client certificate hash (`envoy.transport_sockets.tls`)
  * 3. `envoy_server` Network Filter that contacts external server for list of approved client certs (`envoy.filters.network.client_ssl_auth`)
  * 4. `envoy_server` validates client certificate against CRL (`envoy.transport_sockets.tls`)
  * 5. `envoy_server` -> `upstream server`  requested by client (`envoy.transport_sockets.tls`)


```bash
                     envoy (auth_api_cluster)
                       ^
                       |
                     (TLS)
                       ^
                       |
client ->  (mTLS) -> envoy  -> (TLS) -> upstream                       
```


Specifically, the following envoy constructs are used:

- Steps 2,4
 `envoy.transport_sockets.tls`
  `type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext`

- Steps 5
 `envoy.transport_sockets.tls`
  `type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext`

- Steps 3:
  [extensions.filters.network.client_ssl_auth.v3.ClientSSLAuth](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/network/client_ssl_auth/v3/client_ssl_auth.proto#extensions-filters-network-client-ssl-auth-v3-clientsslauth)


>> NOTE:  you can just enforce mTLS by just following steps 2 ...I added in step 3 as well just for completeness and to show a network mTLS filter.  Also, the configurations show both static client certificate validation *and* dynamic validation (eg, using CRL or calling an external system to get a list of valid certificate hashes).  Finally, the envoy server will respond to the clients TLS request with a stapled OCSP response which is then validated.

---

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

First note the certificate specifications we will use

- `http_server.crt`

This is the certificate the envoy server uses

```bash
$ openssl x509 -in certs/http_server.crt -noout -text
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
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
            Serial Number: 13 (0xd)             <<<<<<<<<<<<<<<<<<
            Signature Algorithm: sha1WithRSAEncryption
            Issuer: C = US, O = Google, OU = Enterprise, CN = Enterprise Subordinate CA
            Validity
                Not Before: Oct 31 18:05:09 2020 GMT
                Not After : Oct 31 18:05:09 2022 GMT
            Subject: C = US, O = Google, OU = Enterprise, CN = client@domain.com
            X509v3 extensions:
                X509v3 Key Usage: critical
                    Digital Signature
                X509v3 Basic Constraints: 
                    CA:FALSE
                X509v3 Extended Key Usage: 
                    TLS Web Client Authentication
                X509v3 Subject Key Identifier: 
                    7C:26:D4:CD:5B:F5:09:A0:68:65:99:92:4F:AD:A5:B7:CC:40:C4:8E
                X509v3 Authority Key Identifier: 
                    keyid:BF:E1:1C:F0:22:48:8F:FC:3B:CF:5D:D9:ED:AE:88:70:21:DF:DD:86
                X509v3 Subject Alternative Name: 
                    DNS:client.domain.com
```

Note the SAN value as well as the serial number (`13 (0D)`) which will be used for CRL based validation


Also, we will generate the digest value (we will use this later to indicate valid certificates:

```bash
$ openssl x509 -in client.crt -outform DER | openssl dgst -sha256 | cut -d" " -f2
  492d412c90b7d1747f02583d03dbf52e009fde113dd454bd5de572bde6595efc

$ openssl x509 -in client.crt -noout -pubkey  | openssl pkey -pubin -outform DER  | openssl dgst -sha256 -binary  | openssl enc -base64
  jAKNnM50a5COFYrdrpWqTSiRP38Lr7GzyDnPWNe39DI=
```

- `certserver.crt`

This is the certificate the external server the envoy_server contacts to acquire the list of valid client certificates

```bash
$ openssl x509 -in certs/certserver.crt -noout -text 
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Subject Alternative Name: 
                DNS:certserver.domain.com
```

### Configuration

1. Download envoy

```
docker cp `docker create envoyproxy/envoy:v1.16-dev`:/usr/local/bin/envoy .
```

2. Run envoy_server

```
./envoy -c server.yaml --base-id 0 -l debug
```

3. Run certificate service

```bash
./envoy -c certsvc.yaml --base-id 1 -l debug
```

4. Access envoy server

Now that each component is running use curl to access the envoy server

```bash
curl -v -H "host: http.domain.com"  \
   --resolve  http.domain.com:8081:127.0.0.1 \
   --cert certs/client.crt \
   --key certs/client.key  \
   --cacert certs/tls-ca-chain.pem \
   --cert-status \
     https://http.domain.com:8081/get
```

The client will establish a mTLS with envoy_server.
Envoy Server will validate the presented client certificate against a list of approved CAs.
Envoy Server will validate the hash of the provided client cert
Envoy Server will contact an external service for a list of approved client certificates

...as mentioned, several steps here are completely redundant (eg, locally validating the client cert *and* contacting an external server for the same)

Anyway, lets take a careful look at `server.yaml`:

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
            validation_context:
              trusted_ca:
                filename: certs/tls-ca-chain.pem
              # crl:
              #   filename: certs/tls-ca.crl
              verify_certificate_spki:
              - "jAKNnM50a5COFYrdrpWqTSiRP38Lr7GzyDnPWNe39DI="   
```

This is the configuration for the downstream connection (i.,e client->envoy_server)


- `validation_context.trusted_ca` defines the root CAs that can sign the client certificate

- `crl` is a reference to a local file that defines the CRL to use in validating a client certificate.  The crl included in this repo actually flags the client certificate as revoked (meaning you can enable that flag and test failure)

- `verify_certificate_spki`  this is a list of the client certificates allowed
  ```bash
    $ openssl x509 -in client.crt -noout -pubkey  | openssl pkey -pubin -outform DER  | openssl dgst -sha256 -binary  | openssl enc -base64
      jAKNnM50a5COFYrdrpWqTSiRP38Lr7GzyDnPWNe39DI=
  ```

- `envoy.filters.network.client_ssl_auth`:  this setting is a network filter to validate the certificate.
   The envoy_server will invoke a REST URL on a designate cluster for the list of acceptable certificate hash.  That is

```json
$ curl -s localhost:18080/v1/certs/list/approved | jq '.'
{
  "certificates": [
    {
      "fingerprint_sha256": "492d412c90b7d1747f02583d03dbf52e009fde113dd454bd5de572bde6595efc"
    }
  ]
}
```
```
$ openssl x509 -in client.crt -outform DER | openssl dgst -sha256 | cut -d" " -f2
  492d412c90b7d1747f02583d03dbf52e009fde113dd454bd5de572bde6595efc
```

- `verify_certificate_spki`: this setting performs a static validation of the provided certificate
```
$ openssl x509 -in client.crt -noout -pubkey  | openssl pkey -pubin -outform DER  | openssl dgst -sha256 -binary  | openssl enc -base64
  jAKNnM50a5COFYrdrpWqTSiRP38Lr7GzyDnPWNe39DI=
```

#### CRL

If you want to see the details of the CRL, run the following.

Note the `Revoked Certificates` list where the serial number is listed

```bash
$ openssl crl -inform PEM -text -noout -in tls-ca.crl 
      Certificate Revocation List (CRL):
              Version 2 (0x1)
              Signature Algorithm: sha1WithRSAEncryption
              Issuer: C = US, O = Google, OU = Enterprise, CN = Enterprise Subordinate CA
              Last Update: Dec 12 14:12:16 2020 GMT
              Next Update: Jan 16 14:12:16 2022 GMT
              CRL extensions:
                  X509v3 Authority Key Identifier: 
                      keyid:BF:E1:1C:F0:22:48:8F:FC:3B:CF:5D:D9:ED:AE:88:70:21:DF:DD:86

                  Authority Information Access: 
                      CA Issuers - URI:http://pki.esodemoapp2.com/ca/tls-ca.cer

                  X509v3 CRL Number: 
                      3
      Revoked Certificates:
          Serial Number: 01
              Revocation Date: Apr 26 00:31:18 2020 GMT
          Serial Number: 0D
              Revocation Date: Dec 12 14:11:52 2020 GMT
```

If you uncomment the section where the CRL is validated, and you invoke the client, you will see an SSL response indicating expired cert

```bash
> GET /get HTTP/1.1
> Host: http.domain.com
> User-Agent: curl/7.72.0
> Accept: */*

* TLSv1.3 (IN), TLS alert, certificate revoked (556):
* OpenSSL SSL_read: error:14094414:SSL routines:ssl3_read_bytes:sslv3 alert certificate revoked, errno 0
* Closing connection 0
curl: (56) OpenSSL SSL_read: error:14094414:SSL routines:ssl3_read_bytes:sslv3 alert certificate revoked, errno 0
```

#### OCSP


Use openssl to test the OCSP Responder:

- Valid server certificate:
```bash
$ cd certs/
$ openssl ocsp -index db_valid/tls-ca.db -port 9999 -rsigner ocsp.crt -rkey ocsp.key -CA tls-ca.crt -text -ndays 500

$ openssl ocsp -CA tls-ca.crt -CAfile tls-ca-ocsp-chain.pem -issuer tls-ca.crt  -cert http_server.crt -url http://localhost:9999 -resp_text

$ openssl ocsp -CA tls-ca.crt -CAfile tls-ca-ocsp-chain.pem -issuer tls-ca.crt  -cert http_server.crt -url http://localhost:9999 -respout http_server_ocsp_resp_valid.bin
    Response verify OK
    http_server.crt: good
      This Update: Dec 17 14:11:55 2020 GMT
      Next Update: May  1 14:11:55 2022 GMT
```

or with openssl client/server

```
$ openssl s_server \
  -status_file http_server_ocsp_resp_valid.bin \
  -cert http_server.crt -key http_server.key \
  -port 8081 -CAfile tls-ca-ocsp-chain.pem \
  -verify_return_error -verify 1

$ openssl s_client \
  -connect localhost:8081 \
  -servername http.domain.com \
  -CAfile tls-ca-chain.pem \
  -cert client.crt \
  -key client.key -tls1_3 -tlsextdebug -status --verify 1


```

on `server.yaml`, set

```yaml
              ocsp_staple:
                filename: certs/http_server_ocsp_resp_valid.bin
```

restart and run curl with `--cert-status` flag or via openssl to just view the OCSP stapled response

```bash
$ curl -vvvvv -H "host: http.domain.com"  --resolve  http.domain.com:8081:127.0.0.1  \
    --cert certs/client.crt  \
    --key certs/client.key  \
    --cacert certs/tls-ca-chain.pem \
    --cert-status \
       https://http.domain.com:8081/get


* Added http.domain.com:8081:127.0.0.1 to DNS cache
* Hostname http.domain.com was found in DNS cache
*   Trying 127.0.0.1:8081...
* Connected to http.domain.com (127.0.0.1) port 8081 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*   CAfile: certs/tls-ca-chain.pem
  CApath: /etc/ssl/certs
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Request CERT (13):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Certificate (11):
* TLSv1.3 (OUT), TLS handshake, CERT verify (15):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* ALPN, server did not agree to a protocol
* Server certificate:
*  subject: C=US; O=Google; OU=Enterprise; CN=http.domain.com
*  start date: Jul 10 19:29:07 2020 GMT
*  expire date: Jul 10 19:29:07 2022 GMT
*  subjectAltName: host "http.domain.com" matched cert's "http.domain.com"
*  issuer: C=US; O=Google; OU=Enterprise; CN=Enterprise Subordinate CA
*  SSL certificate verify ok.
* SSL certificate status: good (0)                                       <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<


> GET /get HTTP/1.1
> Host: http.domain.com
> User-Agent: curl/7.72.0
> Accept: */*
> 
```

- Revoked Server certificate

```bash
cd certs/
openssl ocsp -index db_revoked/tls-ca.db -port 9999 -rsigner ocsp.crt -rkey ocsp.key -CA tls-ca.crt -text -ndays 500

openssl ocsp -CA tls-ca.crt -CAfile tls-ca-ocsp-chain.pem -issuer tls-ca.crt  -cert http_server.crt -url http://localhost:9999 -resp_text

$ openssl ocsp -CA tls-ca.crt -CAfile tls-ca-ocsp-chain.pem -issuer tls-ca.crt  -cert http_server.crt -url http://localhost:9999 -respout http_server_ocsp_resp_revoked.bin
    Response verify OK
    http_server.crt: revoked
      This Update: Dec 17 14:12:51 2020 GMT
      Next Update: May  1 14:12:51 2022 GMT
      Revocation Time: Dec 12 14:11:52 2020 GMT
```

on `server.yaml`,

```yaml
              ocsp_staple:
                filename: certs/http_server_ocsp_resp_revoked.bin
```

```
$ curl -vvvvv -H "host: http.domain.com"  --resolve  http.domain.com:8081:127.0.0.1    \
    --cert certs/client.crt      --key certs/client.key   \
    --cacert certs/tls-ca-chain.pem     --cert-status   https://http.domain.com:8081/get


* Added http.domain.com:8081:127.0.0.1 to DNS cache
* Hostname http.domain.com was found in DNS cache
*   Trying 127.0.0.1:8081...
* Connected to http.domain.com (127.0.0.1) port 8081 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*   CAfile: certs/tls-ca-chain.pem
  CApath: /etc/ssl/certs
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Request CERT (13):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Certificate (11):
* TLSv1.3 (OUT), TLS handshake, CERT verify (15):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* ALPN, server did not agree to a protocol
* Server certificate:
*  subject: C=US; O=Google; OU=Enterprise; CN=http.domain.com
*  start date: Jul 10 19:29:07 2020 GMT
*  expire date: Jul 10 19:29:07 2022 GMT
*  subjectAltName: host "http.domain.com" matched cert's "http.domain.com"
*  issuer: C=US; O=Google; OU=Enterprise; CN=Enterprise Subordinate CA
*  SSL certificate verify ok.
* SSL certificate status: revoked (1)                                <<<<<<<<<<<<<<<<<<<<<<<<<<<
* SSL certificate revocation reason: (UNKNOWN) (-1)
* Closing connection 0
* TLSv1.3 (OUT), TLS alert, close notify (256):
curl: (91) SSL certificate revocation reason: (UNKNOWN) (-1)
```
