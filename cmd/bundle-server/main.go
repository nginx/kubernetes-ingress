package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func main() {
	port := flag.Int("port", 8443, "Port to listen on")
	healthPort := flag.Int("health-port", 8080, "Port for the plain-HTTP health endpoint (no TLS, safe for kubelet probes)")
	bundleDir := flag.String("bundle-dir", "./bundles", "Directory containing bundle files to serve")
	tlsCert := flag.String("tls-cert", "", "Path to TLS certificate (enables HTTPS)")
	tlsKey := flag.String("tls-key", "", "Path to TLS private key (enables HTTPS)")
	clientCA := flag.String("client-ca", "", "Path to client CA certificate (enables mTLS)")
	flag.Parse()

	if err := os.MkdirAll(*bundleDir, 0o750); err != nil {
		log.Fatalf("Failed to create bundle directory %s: %v", *bundleDir, err)
	}

	// Plain HTTP mux for kubelet liveness/readiness probes only.
	// Deliberately separate from the mTLS server so probes never require a client cert.
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
	go func() {
		healthAddr := fmt.Sprintf(":%d", *healthPort)
		log.Printf("Health endpoint listening on http://localhost%s", healthAddr)
		if err := http.ListenAndServe(healthAddr, healthMux); err != nil { //nolint:gosec
			log.Fatalf("Health server error: %v", err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/bundles/", bundleHandler(*bundleDir))

	addr := fmt.Sprintf(":%d", *port)

	if *tlsCert != "" && *tlsKey != "" {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		if *clientCA != "" {
			caCert, err := os.ReadFile(*clientCA)
			if err != nil {
				log.Fatalf("Failed to read client CA: %v", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caCert) {
				log.Fatal("Failed to parse client CA certificate")
			}
			tlsConfig.ClientCAs = pool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			log.Printf("mTLS enabled with client CA: %s", *clientCA)
		}

		server := &http.Server{
			Addr:      addr,
			Handler:   mux,
			TLSConfig: tlsConfig,
		}

		log.Printf("Bundle server listening on https://localhost%s (bundle-dir=%s)", addr, *bundleDir)
		log.Fatal(server.ListenAndServeTLS(*tlsCert, *tlsKey))
	} else {
		log.Printf("Bundle server listening on http://localhost%s (bundle-dir=%s)", addr, *bundleDir)
		log.Printf("WARNING: Running without TLS. For mTLS, provide --tls-cert and --tls-key flags.")
		server := &http.Server{
			Addr:    addr,
			Handler: mux,
		}
		log.Fatal(server.ListenAndServe())
	}
}

func bundleHandler(bundleDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		filename := path.Base(r.URL.Path)
		if filename == "." || filename == "/" || strings.Contains(filename, "..") {
			http.Error(w, "invalid filename", http.StatusBadRequest)
			return
		}

		filePath := filepath.Join(bundleDir, filename)

		switch r.Method {
		case http.MethodGet, http.MethodHead:
			handleGet(w, r, filePath)
		case http.MethodPost:
			handleUpload(w, r, filePath)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func handleGet(w http.ResponseWriter, r *http.Request, filePath string) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "bundle not found", http.StatusNotFound)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	etag := computeETag(data)
	w.Header().Set("ETag", etag)

	if match := r.Header.Get("If-None-Match"); match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.WriteHeader(http.StatusOK)
	if _, writeErr := w.Write(data); writeErr != nil {
		log.Printf("Error writing response: %v", writeErr)
	}
}

func handleUpload(w http.ResponseWriter, r *http.Request, filePath string) {
	const maxUploadSize = 256 << 20
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	// Write atomically via a temp file in the same directory, then rename.
	// This prevents NIC from downloading a partially-written file if a poll
	// fires concurrently with this upload.
	tmpFile, err := os.CreateTemp(filepath.Dir(filePath), ".upload-*.tmp")
	if err != nil {
		http.Error(w, "failed to create temp file", http.StatusInternalServerError)
		return
	}
	tmpPath := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			os.Remove(tmpPath) //nolint:errcheck
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		http.Error(w, "failed to write bundle", http.StatusInternalServerError)
		return
	}
	if err := tmpFile.Close(); err != nil {
		http.Error(w, "failed to close temp file", http.StatusInternalServerError)
		return
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		http.Error(w, "failed to set permissions", http.StatusInternalServerError)
		return
	}
	if err := os.Rename(tmpPath, filePath); err != nil {
		http.Error(w, "failed to write bundle", http.StatusInternalServerError)
		return
	}
	cleanup = false

	etag := computeETag(data)
	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Bundle uploaded successfully (ETag: %s)\n", etag)
	log.Printf("Bundle uploaded: %s (size=%d, etag=%s)", filepath.Base(filePath), len(data), etag)
}

func computeETag(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf(`"%x"`, h[:8])
}
