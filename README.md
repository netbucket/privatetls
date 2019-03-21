# PrivateTLS
A Golang library for quickly and easily starting a private HTTPS server with a self-signed TLS certificate, without requiring any preparatory work, such as pre-generating a cert with `openssl`. PrivateTLS generates a self-sigend certificate
in memory, with no need for disk I/O. 

This library is meant for use with private HTTPS services, where the use of a trusted third party Certificate Authority is not desirable, or not practical. 

For all other situations, please *do not use this library*. Instead, use any available 
commercial CA providers, or use the free service from  [Let's Encrypt](https://letsencrypt.org/).

## Quick Start
The easiest way to generate a certificate and start the server, is to use the 
`privatetls.StartHTTPSListener()` function:

```go
package main

import (
	"fmt"
	"net/http"

	"github.com/netbucket/privatetls"
)

func main() {
	http.HandleFunc("/", helloHandler)

	// Generate a self-sgined cert and start an HTTPS listener on port 8443
	privatetls.StartHTTPSListener(":8443")
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello from PrivateTLS!")
}
```
The call to `StartHTTPSListener` will generate a self-signed RSA based TLS certificate with a random 2048 bit key. The certificate is valid for 1 year.

## More control
If you want more control over the TLS configuration, use `privatetls.NewCert()` to
generate a certificate and return it back to you:
```go
package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"github.com/netbucket/privatetls"
)

func main() {
	http.HandleFunc("/", helloHandler)

	s := http.Server{}

	// Use port 8443 for the TLS/HTTPS server
	s.Addr = ":8443"

	// Generate a self-sifned certificate
	selfSignedCert, err := privatetls.NewCert()

	if err != nil {
		log.Fatal(err)
	}

	// Assign the generated self-signed cert to this server
	s.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert},
	}

	// Start the TLS server. Use blank cert and key file values.
	s.ListenAndServeTLS("", "")

}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello from PrivateTLS!")
}
```

That's it. 

