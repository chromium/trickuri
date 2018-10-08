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

// Generates test cases for URL spoofing vulnerabilities.
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
	"runtime"
	"strconv"
	"time"
)

// Command line flags
var (
	port      = flag.Int("p", 1270, "port on which to listen")
	httpsPort = flag.Int("h", 8443, "port on which the HTTPS proxy will listen")
	directory = flag.String("d", userHomeDir()+"/.trickuri", "default directory on which to save certificates")
)

// Globals
var (
	caKey       crypto.PrivateKey
	caCert      *x509.Certificate
	certMap     map[string]*tls.Certificate
	lastTunHost string
)

// Multi-platform code to get user home directory, used for the default certificate storage path.
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

// Common certificate generation code
func createCertificateTemplate() (*x509.Certificate, error) {
	notBefore := time.Now().AddDate(0, 0, -7) // Mitigate clock-skew between this server and the client.
	notAfter := notBefore.AddDate(1, 0, 7)    // Certs are valid for one year from now.
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"TrickUri Interception Certificate"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	return certTemplate, nil
}

// Returns a root certificate and its key.
func createRootCertificate() ([]byte, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	certTemplate, err := createCertificateTemplate()
	if err != nil {
		return nil, nil, err
	}

	var cerBytes []byte
	certTemplate.IsCA = true
	certTemplate.MaxPathLen = 0
	certTemplate.MaxPathLenZero = true
	certTemplate.Subject = pkix.Name{Organization: []string{"TrickUri Root"}}
	hash := sha256.Sum256(priv.PublicKey.N.Bytes())
	certTemplate.SubjectKeyId = hash[:]
	certTemplate.KeyUsage |= x509.KeyUsageCertSign
	cerBytes, err = x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	return cerBytes, priv, nil
}

// Writes |certificate| to |filename|.cer and |key| to |filename|.pem.
func writeCertificate(certificate []byte, key *rsa.PrivateKey, filename string) error {
	certOut, err := os.Create(*directory + "/" + filename + ".cer")
	if err != nil {
		return err
	}
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	certOut.Close()
	if err != nil {
		return err
	}

	keyOut, err := os.OpenFile(*directory+"/"+filename+".pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	keyOut.Close()
	if err != nil {
		return err
	}
	return nil
}

// If a root certificate and key exist in the trickuri directory, loads them, otherwise creates them.
func loadOrCreateRootCertificate() (tls.Certificate, error) {
	rootKeys, err := tls.LoadX509KeyPair(*directory+"/root.cer", *directory+"/root.pem")
	if err != nil {
		log.Println("root.cer failed to load. Recreating root certificate.")
		rootCert, rootKey, err := createRootCertificate()
		if err != nil {
			return tls.Certificate{}, err
		}
		if err := writeCertificate(rootCert, rootKey, "root"); err != nil {
			return tls.Certificate{}, err
		}
		return tls.LoadX509KeyPair(*directory+"/root.cer", *directory+"/root.pem")
	}
	return rootKeys, err
}

// Generates a certificate for |hostname|.
func generateCertificate(hostname string) (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	certTemplate, err := createCertificateTemplate()
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(hostname); ip != nil {
		certTemplate.IPAddresses = append(certTemplate.IPAddresses, ip)
	} else {
		certTemplate.DNSNames = append(certTemplate.DNSNames, hostname)
	}
	cerBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{cerBytes},
		PrivateKey:  priv,
	}, nil
}

// Retrieves the certificate for |info| if it has been created before, otherwise generates it and returns it.
func certificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var hostname string
	if len(info.ServerName) > 0 {
		hostname = info.ServerName
	} else {
		// If the SNI hostname is empty (e.g., for IP addresses), create a certificate for the last tunneled hostname.
		hostname = lastTunHost
	}
	if cert := certMap[hostname]; cert != nil {
		return cert, nil
	}
	cert, err := generateCertificate(hostname)
	if err != nil {
		return nil, err
	}
	certMap[hostname] = cert
	return cert, nil
}

// Serve a proxy configuration script that directs the client to go direct for responses
// that should not be generated from this tool. This helps ensure that Chrome/Windows/etc
// are not unduly affected by our HTTP(S) interceptions.
func serveProxyConfigurationScript(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `function FindProxyForURL(url, host) {
			// Bypass list. See https://findproxyforurl.com/pac-functions/ for functions.
			if (shExpMatch(host, "*.google.com")) return "DIRECT";
			if (shExpMatch(host, "*.gstatic.com")) return "DIRECT";
			if (shExpMatch(host, "*.googleusercontent.com")) return "DIRECT";
			if (shExpMatch(host, "*.googleapis.com")) return "DIRECT";
			if (shExpMatch(host, "*.microsoft.com")) return "DIRECT";
			if (dnsDomainLevels(host) < 1) return "DIRECT";

			// Return a response from TrickUri.
			return "PROXY localhost:%d";
		}`,
		*port)
}

// Serve a printout of the request |r|.
func serveEcho(w http.ResponseWriter, r *http.Request) {
	err := r.Write(w)
	if err != nil {
		log.Println(err)
	}
}

func serveRootCert(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, *directory+"/root.cer")
}

// Handler for HTTP tunneling.
func tunnelHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		// This is a request that doesn't require tunneling, use the default handler.
		httpHandler(w, r)
		return
	}
	// All https requests will be forwarded to the HTTPS proxy running on the set HTTPS port
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
	// Save a copy of the last tunneled hostname, used for certificate generation if SNI is not available.
	lastTunHost = r.URL.Hostname()
	go forward(dst, hijackedConn)
	go forward(hijackedConn, dst)
}

func forward(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

func httpHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.EscapedPath() == "/proxy.pac" {
		serveProxyConfigurationScript(w, r)
		return
	}
	if r.URL.EscapedPath() == "/echo" {
		serveEcho(w, r)
		return
	}
	if r.URL.EscapedPath() == "/root.cer" {
		serveRootCert(w, r)
		return
	}
	testcaseHandler := http.FileServer(http.Dir("testcases"))
	testcaseHandler.ServeHTTP(w, r)
}

func main() {
	flag.Parse()
	err := os.MkdirAll(*directory, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
	certMap = make(map[string]*tls.Certificate)
	rootCert, err := loadOrCreateRootCertificate()
	if err != nil {
		log.Fatal(err)
	}
	caCert, err = x509.ParseCertificate(rootCert.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}
	caKey = rootCert.PrivateKey

	log.Printf("Download the root certificate at http://localhost:%d/root.cer and import it into browser/OS certificate store.", *port)
	log.Printf("Set your proxy to \"http://localhost:%[1]d/proxy.pac\" or localhost:%[1]d. Using pac file will pass through requests to google.com and microsoft.com for common Chrome/Windows requests.", *port)
	log.Println("Ready for requests")

	cfg := &tls.Config{
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		GetCertificate:           certificate,
	}
	httpServer := http.Server{
		Addr:    "localhost:1270",
		Handler: http.HandlerFunc(tunnelHandler),
	}
	httpsServer := http.Server{
		Addr:      "localhost:" + strconv.Itoa(*httpsPort),
		TLSConfig: cfg,
		Handler:   http.HandlerFunc(httpHandler),
	}
	go func() {
		if err := httpsServer.ListenAndServeTLS("", ""); err != nil {
			log.Fatal(err)
		}
	}()
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
