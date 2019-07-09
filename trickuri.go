// Copyright 2018 The Trickuri Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Trickuri generates test cases for URL spoofing vulnerabilities.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	port      = flag.Int("p", 1270, "port on which to listen")
	httpsPort = flag.Int("h", 8443, "port on which the HTTPS proxy will listen")
	directory = flag.String("d", userHomeDir()+"/.config/trickuri", "default directory in which to save certificates")
	testIndex = flag.String("i", "index.html", "default file location containing test index")
)

var (
	caKey   crypto.PrivateKey
	caCert  *x509.Certificate
	certMap = make(map[string]*tls.Certificate)

	// TODO: fix the data race around this variable, either with a lock on this
	// variable, or (possibly better) by using a channel.
	lastTunneledHost string
)

// userHomeDir returns a suitable directory for the default certificate storage path.
func userHomeDir() string {
	if runtime.GOOS == "windows" {
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home
	}
	return os.Getenv("HOME")
}

// newCertificate returns an initialized certificate with usable values.
func newCertificate() (*x509.Certificate, error) {
	maxSerial := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, maxSerial)
	if err != nil {
		return nil, err
	}

	return &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"TrickUri Interception Certificate"},
		},
		NotBefore:             time.Now().AddDate(0, 0, -7), // mitigate clock-skew
		NotAfter:              time.Now().AddDate(1, 0, 7),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}, nil
}

// newRootCertificate returns a root certificate and its key.
func newRootCertificate() ([]byte, *rsa.PrivateKey, error) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	cert, err := newCertificate()
	if err != nil {
		return nil, nil, err
	}
	cert.IsCA = true
	cert.MaxPathLen = 0
	cert.MaxPathLenZero = true
	cert.Subject = pkix.Name{Organization: []string{"TrickUri Root"}}
	hash := sha256.Sum256(private.PublicKey.N.Bytes())
	cert.SubjectKeyId = hash[:]
	cert.KeyUsage |= x509.KeyUsageCertSign

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &private.PublicKey, private)
	if err != nil {
		return nil, nil, err
	}

	return certBytes, private, nil
}

// writeCertificate writes the provided certificate and key to files in the specified paths.
func writeCertificate(cert []byte, key *rsa.PrivateKey, certPath, keyPath string) error {
	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
		return err
	}
	if err := certFile.Close(); err != nil {
		return err
	}

	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return err
	}
	if err := keyFile.Close(); err != nil {
		return err
	}

	return nil
}

// rootCertificate returns a root certificate, either loaded from the given
// directory, or created and saved.
func rootCertificate(directory string) (tls.Certificate, error) {
	certPath := path.Join(directory, "root.cer")
	keyPath := path.Join(directory, "root.pem")

	rootKeys, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Println("Failed to load root certificate. Recreating root certificate.")
		rootCert, rootKey, err := newRootCertificate()
		if err != nil {
			return tls.Certificate{}, err
		}
		if err := writeCertificate(rootCert, rootKey, certPath, keyPath); err != nil {
			return tls.Certificate{}, err
		}
		return tls.LoadX509KeyPair(certPath, keyPath)
	}
	return rootKeys, err
}

// newHostCertificate returns a certificate for the given hostname.
func newHostCertificate(hostname string) (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	cert, err := newCertificate()
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(hostname); ip != nil {
		cert.IPAddresses = append(cert.IPAddresses, ip)
	} else {
		cert.DNSNames = append(cert.DNSNames, hostname)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  priv,
	}, nil
}

// certificate returns a matching certificate, either from a cache or by generating a new one.
func certificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var hostname string
	if len(info.ServerName) > 0 {
		hostname = info.ServerName
	} else {
		// If the SNI hostname is empty (e.g., for IP addresses), create a certificate for the last tunneled hostname.
		hostname = lastTunneledHost
	}

	if cert, ok := certMap[hostname]; ok {
		return cert, nil
	}

	cert, err := newHostCertificate(hostname)
	if err != nil {
		return nil, err
	}
	certMap[hostname] = cert

	return cert, nil
}

const pacFmt = `
function FindProxyForURL(url, host) {
        // Bypass list. See https://findproxyforurl.com/pac-functions/ for functions.
        if (shExpMatch(host, "*.google.com")) return "DIRECT";
        if (shExpMatch(host, "*.gstatic.com")) return "DIRECT";
        if (shExpMatch(host, "*.googleusercontent.com")) return "DIRECT";
        if (shExpMatch(host, "*.googleapis.com")) return "DIRECT";
        if (shExpMatch(host, "*.microsoft.com")) return "DIRECT";
        if (dnsDomainLevels(host) < 1) return "DIRECT";

        // Return a response from TrickUri.
        return "PROXY localhost:%d";
}`

// servePAC serves a proxy auto configuration script that directs the client to
// go direct for responses that should not be generated from this tool. This helps
// ensure that Chrome/Windows/etc are not unduly affected by our HTTP(S) interceptions.
func servePAC(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, pacFmt, *port)
}

func serveEcho(w http.ResponseWriter, r *http.Request) {
	if err := r.Write(w); err != nil {
		log.Println(err)
	}
}

func serveRootCert(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, *directory+"/root.cer")
}

// serveHttpAuth returns whether the request contains HTTP Auth headers.
// When it does, it also writes a 401 Unauthorized response.
func serveHttpAuth(w http.ResponseWriter, r *http.Request) bool {
	if _, _, ok := r.BasicAuth(); ok {
		return true
	}
	w.Header().Set("WWW-Authenticate", "Basic realm=test")
	w.WriteHeader(401)
	w.Write([]byte("Unauthorized"))
	return false
}

func tunnelHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		// This is a request that doesn't require tunneling, use the default handler.
		httpHandler(w, r)
		return
	}

	// All https requests will be forwarded to the HTTPS proxy running on the set HTTPS port.
	httpsHost := "localhost:" + strconv.Itoa(*httpsPort)
	dst, err := net.DialTimeout("tcp", httpsHost, 3*time.Second)
	if err != nil {
		http.Error(w, "forwarding to "+httpsHost+" failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking is not supported", http.StatusInternalServerError)
		return
	}
	hijackedConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, "error hijacking connection", http.StatusInternalServerError)
		return
	}

	// Save for certificate generation if SNI is not available.
	lastTunneledHost = r.URL.Hostname()

	go forward(dst, hijackedConn)
	go forward(hijackedConn, dst)
}

func forward(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

func httpHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.EscapedPath() {
	case "/proxy.pac":
		servePAC(w, r)
		return
	case "/echo":
		serveEcho(w, r)
		return
	case "/root.cer":
		serveRootCert(w, r)
		return
	case "/web-feature-tests/http-auth/":
		if !serveHttpAuth(w, r) {
			return
		}
	}

	if strings.HasPrefix(r.URL.EscapedPath(), "/web-feature-tests") {
		tc := http.FileServer(http.Dir("."))
		tc.ServeHTTP(w, r)
		return
	}

	// An index explaining how to use the different testcases.
	http.ServeFile(w, r, *testIndex)
}

const welcomeFmt = `

----Welcome to Trickuri!----

This tool facilitates testing of applications that displays URLs to users.
Trickuri is ready to receive requests.

1.) Download the root certificate at http://localhost:%d/root.cer and import it
into your browser/OS certificate store. See README.md for instructions on how to
import a root certificate.

2.) Set the proxy server of the application under test to
http://localhost:%[1]d/proxy.pac or localhost:%[1]d. Using the PAC file will
pass through requests to google.com and microsoft.com for common Chrome/Windows
requests. See https://www.chromium.org/developers/design-documents/network-settings
for instructions on configuring Chrome's proxy server, if you are testing Chrome.

3.) Visit https://example.com/ (or any other URL) to see a list of test cases.

`

func main() {
	flag.Parse()

	if err := os.MkdirAll(*directory, os.ModePerm); err != nil {
		log.Fatal(err)
	}

	rootCert, err := rootCertificate(*directory)
	if err != nil {
		log.Fatal(err)
	}
	caCert, err = x509.ParseCertificate(rootCert.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}
	caKey = rootCert.PrivateKey

	fmt.Printf(welcomeFmt, *port)

	httpsServer := http.Server{
		Addr: "localhost:" + strconv.Itoa(*httpsPort),
		TLSConfig: &tls.Config{
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
			GetCertificate:           certificate,
		},
		Handler: http.HandlerFunc(httpHandler),
	}
	go func() {
		if err := httpsServer.ListenAndServeTLS("", ""); err != nil {
			log.Fatal(err)
		}
	}()

	httpServer := http.Server{
		Addr:    "localhost:" + strconv.Itoa(*port),
		Handler: http.HandlerFunc(tunnelHandler),
	}
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
