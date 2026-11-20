#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Asserts what the chart renders for apiTLS in each state, which `helm lint`
# does not check: the Secret mounts, the SERVER_TLS_* environment, and probes
# the kubelet can still pass once the API serves TLS.
#
# Needs helm. Resolves the chart relative to this script, so it runs from
# anywhere; CHART overrides that.

set -euo pipefail

CHART="${CHART:-"$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/deploy/charts/controller"}"
[[ -d "${CHART}" ]] || { echo "chart not found at ${CHART}" >&2; exit 2; }

failures=0

# The default values ship no probes, so every render sets both as httpGet.
render() {
  helm template cwe "${CHART}" \
    --set livenessProbe.httpGet.path=/healthz --set livenessProbe.httpGet.port=http \
    --set readinessProbe.httpGet.path=/readyz --set readinessProbe.httpGet.port=http \
    "$@"
}

# want <description> <pattern> <rendered>
want() {
  if grep -qE "$2" <<<"$3"; then
    printf '  ok    %s\n' "$1"
  else
    printf '  FAIL  %s (expected to find: %s)\n' "$1" "$2" >&2
    failures=$((failures + 1))
  fi
}

# absent <description> <pattern> <rendered>
absent() {
  if grep -qE "$2" <<<"$3"; then
    printf '  FAIL  %s (should not have rendered: %s)\n' "$1" "$2" >&2
    failures=$((failures + 1))
  else
    printf '  ok    %s\n' "$1"
  fi
}

# count <description> <pattern> <expected count> <rendered>
count() {
  local got
  got="$(grep -cE "$2" <<<"$4" || true)"
  if [[ "${got}" == "$3" ]]; then
    printf '  ok    %s\n' "$1"
  else
    printf '  FAIL  %s (expected %s of %s, got %s)\n' "$1" "$3" "$2" "${got}" >&2
    failures=$((failures + 1))
  fi
}

# wantfail <description> <pattern> <helm args...>
wantfail() {
  local desc="$1" pattern="$2"; shift 2
  local out
  if out="$(render "$@" 2>&1)"; then
    printf '  FAIL  %s (render succeeded; expected it to fail)\n' "${desc}" >&2
    failures=$((failures + 1))
  elif grep -qE "${pattern}" <<<"${out}"; then
    printf '  ok    %s\n' "${desc}"
  else
    printf '  FAIL  %s (failed, but not with: %s)\n' "${desc}" "${pattern}" >&2
    failures=$((failures + 1))
  fi
}

echo "apiTLS unset"
plain="$(render)"
absent "no TLS environment" 'SERVER_TLS_' "${plain}"
absent "no TLS volume" 'name: api-tls' "${plain}"
absent "probes keep the default scheme" 'scheme: HTTPS' "${plain}"
count "both probes are httpGet" 'httpGet:' 2 "${plain}"

echo "apiTLS.secretName"
tls="$(render --set apiTLS.secretName=nvke-api-tls)"
want "Secret volume" 'secretName: nvke-api-tls' "${tls}"
want "mount" 'mountPath: /etc/nvke/api-tls$' "${tls}"
want "cert path" 'value: /etc/nvke/api-tls/tls.crt' "${tls}"
want "key path" 'value: /etc/nvke/api-tls/tls.key' "${tls}"
absent "no client CA" 'SERVER_TLS_CLIENT_CA_FILE' "${tls}"
count "both probes use scheme HTTPS" 'scheme: HTTPS' 2 "${tls}"
want "Reloader restarts the pod on a new certificate" 'secret.reloader.stakater.com/reload: "nvke-api-tls"' "${tls}"

echo "apiTLS.secretName and apiTLS.clientCASecretName"
mtls="$(render --set apiTLS.secretName=nvke-api-tls --set apiTLS.clientCASecretName=nvke-api-client-ca)"
want "client CA Secret volume" 'secretName: nvke-api-client-ca' "${mtls}"
want "client CA path" 'value: /etc/nvke/api-client-ca/ca.crt' "${mtls}"
count "both probes are tcpSocket" 'tcpSocket:' 2 "${mtls}"
absent "no httpGet probe the kubelet cannot pass" 'httpGet:' "${mtls}"
want "Reloader watches both Secrets" 'secret.reloader.stakater.com/reload: "nvke-api-tls,nvke-api-client-ca"' "${mtls}"

echo "refused values"
wantfail "client CA without a server certificate" 'apiTLS.clientCASecretName requires apiTLS.secretName' \
  --set apiTLS.clientCASecretName=nvke-api-client-ca

if ((failures > 0)); then
  echo "${failures} assertion(s) failed" >&2
  exit 1
fi
