// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dsx-ai-factory/nvke/controller/internal/config"
)

func TestValidateRejectsIncompleteServerTLSSettings(t *testing.T) {
	base := config.Config{
		CertRenewalInterval:           12 * time.Hour,
		CertRenewalThresholdDays:      30,
		CertificateInspectionInterval: time.Hour,
		CertificateObservationMaxAge:  3 * time.Hour,
		CertificateWarningDays:        45,
		MetricsListenAddress:          "127.0.0.1:9090",
		DBConnectionString:            "postgres://cwe:strong@localhost:5432/cwe?sslmode=disable",
		SpireServerAPIAddress:         "spire-server.spire-server.svc.cluster.local:8081",
		SpireJoinTokenTTL:             time.Hour,
		NodeAgent:                     config.NodeAgentConfig{SpireAttestationMethod: config.SpireAttestationMethodTPM},
	}
	require.NoError(t, base.Validate(), "base config must be valid before TLS settings are applied")

	tests := []struct {
		name    string
		cert    string
		key     string
		ca      string
		wantErr string
	}{
		{name: "no TLS settings serve plain HTTP"},
		{name: "cert and key enable TLS", cert: "/tls/tls.crt", key: "/tls/tls.key"},
		{name: "cert key and client CA enable mutual TLS", cert: "/tls/tls.crt", key: "/tls/tls.key", ca: "/tls/ca.crt"},
		{name: "cert without key names the missing key", cert: "/tls/tls.crt", wantErr: "SERVER_TLS_KEY_FILE"},
		{name: "key without cert names the missing cert", key: "/tls/tls.key", wantErr: "SERVER_TLS_CERT_FILE"},
		{name: "client CA without cert and key is rejected", ca: "/tls/ca.crt", wantErr: "SERVER_TLS_CLIENT_CA_FILE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			cfg.ServerTLSCertFile = tt.cert
			cfg.ServerTLSKeyFile = tt.key
			cfg.ServerTLSClientCAFile = tt.ca

			err := cfg.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
