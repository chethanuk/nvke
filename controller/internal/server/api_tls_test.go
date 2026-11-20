// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dsx-ai-factory/nvke/controller/internal/config"
	"github.com/dsx-ai-factory/nvke/controller/internal/server"
	"github.com/dsx-ai-factory/nvke/controller/internal/testutil"
)

// testCA is an in-test certificate authority that writes PEM files to a temp dir.
type testCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	pool    *x509.CertPool
	pemPath string
}

func newTestCA(t *testing.T, dir, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	path := filepath.Join(dir, name+".crt")
	writePEM(t, path, "CERTIFICATE", der)
	return &testCA{cert: cert, key: key, pool: pool, pemPath: path}
}

// issue signs a leaf certificate and returns its cert and key file paths.
func (ca *testCA) issue(t *testing.T, dir, name string, usage x509.ExtKeyUsage) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	certPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")
	writePEM(t, certPath, "CERTIFICATE", der)
	writePEM(t, keyPath, "EC PRIVATE KEY", keyDER)
	return certPath, keyPath
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600))
}

type testPKI struct {
	ca, otherCA               *testCA
	serverCert, serverKey     string
	clientCert, clientKey     string
	strangerCert, strangerKey string
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	dir := t.TempDir()
	p := testPKI{ca: newTestCA(t, dir, "ca"), otherCA: newTestCA(t, dir, "other-ca")}
	p.serverCert, p.serverKey = p.ca.issue(t, dir, "server", x509.ExtKeyUsageServerAuth)
	p.clientCert, p.clientKey = p.ca.issue(t, dir, "client", x509.ExtKeyUsageClientAuth)
	p.strangerCert, p.strangerKey = p.otherCA.issue(t, dir, "stranger", x509.ExtKeyUsageClientAuth)
	return p
}

// startWorkerServer builds the server from the environment and serves it the
// way the worker does: TLS when NewServer configured it, plain HTTP otherwise.
func startWorkerServer(t *testing.T, env map[string]string) (*http.Server, string) {
	t.Helper()
	t.Setenv("CONTROLLER_CONFIG_PATH", "unused.yaml")
	for k, v := range env {
		t.Setenv(k, v)
	}
	cfg, err := config.ParseConfigFromEnv()
	require.NoError(t, err)
	cfg.ProfilesDir = "./profiles"

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	srv, err := server.NewServer(cfg, logger, &testutil.MockDB{}, nil, nil, nil)
	require.NoError(t, err)

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		if srv.TLSConfig != nil {
			done <- srv.ServeTLS(ln, "", "")
			return
		}
		done <- srv.Serve(ln)
	}()
	t.Cleanup(func() {
		require.NoError(t, srv.Close())
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("serve returned %v", err)
		}
	})
	return srv, ln.Addr().String()
}

func httpsClient(t *testing.T, roots *x509.CertPool, certFile, keyFile string) *http.Client {
	t.Helper()
	tlsCfg := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	if certFile != "" {
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		require.NoError(t, err)
		tlsCfg.Certificates = []tls.Certificate{pair}
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
}

func TestAPIServesHealthzOverConfiguredTransport(t *testing.T) {
	pki := newTestPKI(t)
	tlsEnv := map[string]string{"SERVER_TLS_CERT_FILE": pki.serverCert, "SERVER_TLS_KEY_FILE": pki.serverKey}
	mtlsEnv := map[string]string{
		"SERVER_TLS_CERT_FILE":      pki.serverCert,
		"SERVER_TLS_KEY_FILE":       pki.serverKey,
		"SERVER_TLS_CLIENT_CA_FILE": pki.ca.pemPath,
	}

	tests := []struct {
		name       string
		env        map[string]string
		scheme     string
		clientCert string
		clientKey  string
		wantTLS    bool
		wantOK     bool
	}{
		{name: "no TLS settings serve plain HTTP", scheme: "http", wantOK: true},
		{name: "TLS serves HTTPS", env: tlsEnv, scheme: "https", wantTLS: true, wantOK: true},
		{name: "TLS refuses plain HTTP", env: tlsEnv, scheme: "http", wantTLS: true},
		{
			name: "TLS without client CA accepts a client certificate it does not check", env: tlsEnv, scheme: "https",
			clientCert: pki.strangerCert, clientKey: pki.strangerKey, wantTLS: true, wantOK: true,
		},
		{name: "client CA rejects a client without a certificate", env: mtlsEnv, scheme: "https", wantTLS: true},
		{
			name: "client CA accepts a client certificate it signed", env: mtlsEnv, scheme: "https",
			clientCert: pki.clientCert, clientKey: pki.clientKey, wantTLS: true, wantOK: true,
		},
		{
			name: "client CA rejects a client certificate from another CA", env: mtlsEnv, scheme: "https",
			clientCert: pki.strangerCert, clientKey: pki.strangerKey, wantTLS: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, addr := startWorkerServer(t, tt.env)
			assert.Equal(t, tt.wantTLS, srv.TLSConfig != nil, "TLSConfig presence")

			client := httpsClient(t, pki.ca.pool, tt.clientCert, tt.clientKey)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, tt.scheme+"://"+addr+"/healthz", http.NoBody)
			require.NoError(t, err)
			resp, err := client.Do(req)
			if tt.wantOK {
				require.NoError(t, err)
				defer resp.Body.Close()
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				return
			}
			if err == nil {
				defer resp.Body.Close()
				assert.NotEqual(t, http.StatusOK, resp.StatusCode, "request must not succeed")
			}
		})
	}
}

func TestNewServerRejectsUnusableTLSFiles(t *testing.T) {
	pki := newTestPKI(t)
	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage.pem")
	require.NoError(t, os.WriteFile(garbage, []byte("not a pem file\n"), 0o600))
	noCerts := filepath.Join(dir, "no-certs.pem")
	keyPEM, err := os.ReadFile(pki.clientKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(noCerts, keyPEM, 0o600))
	missing := filepath.Join(dir, "missing.pem")

	tests := []struct {
		name string
		cfg  config.Config
	}{
		{name: "missing cert file", cfg: config.Config{ServerTLSCertFile: missing, ServerTLSKeyFile: pki.serverKey}},
		{name: "missing key file", cfg: config.Config{ServerTLSCertFile: pki.serverCert, ServerTLSKeyFile: missing}},
		{name: "cert and key do not match", cfg: config.Config{ServerTLSCertFile: pki.serverCert, ServerTLSKeyFile: pki.clientKey}},
		{name: "garbage cert file", cfg: config.Config{ServerTLSCertFile: garbage, ServerTLSKeyFile: pki.serverKey}},
		{
			name: "missing client CA file",
			cfg:  config.Config{ServerTLSCertFile: pki.serverCert, ServerTLSKeyFile: pki.serverKey, ServerTLSClientCAFile: missing},
		},
		{
			name: "client CA file without PEM certificates",
			cfg:  config.Config{ServerTLSCertFile: pki.serverCert, ServerTLSKeyFile: pki.serverKey, ServerTLSClientCAFile: noCerts},
		},
		{
			name: "client CA file that is not PEM",
			cfg:  config.Config{ServerTLSCertFile: pki.serverCert, ServerTLSKeyFile: pki.serverKey, ServerTLSClientCAFile: garbage},
		},
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg.ProfilesDir = "./profiles"
			srv, err := server.NewServer(tt.cfg, logger, &testutil.MockDB{}, nil, nil, nil)
			require.Error(t, err)
			assert.Nil(t, srv)
		})
	}
}

func TestNewServerRequiresVerifiedClientCertWhenClientCAIsSet(t *testing.T) {
	pki := newTestPKI(t)
	cfg := config.Config{
		ProfilesDir:           "./profiles",
		ServerTLSCertFile:     pki.serverCert,
		ServerTLSKeyFile:      pki.serverKey,
		ServerTLSClientCAFile: pki.ca.pemPath,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	srv, err := server.NewServer(cfg, logger, &testutil.MockDB{}, nil, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, srv.TLSConfig)
	assert.Len(t, srv.TLSConfig.Certificates, 1)
	assert.Equal(t, tls.RequireAndVerifyClientCert, srv.TLSConfig.ClientAuth)
	assert.NotNil(t, srv.TLSConfig.ClientCAs)
}
