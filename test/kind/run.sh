#!/usr/bin/env bash
# Stand up a kind cluster with cert-manager, Contour and a small test app, then
# run internal/e2e's TestKindCertManagerACME against it: cert-manager enrols
# over ACME (http-01) with an in-process CryptOS Intermediate running on this
# host, and the test checks the chain, the SANs, the node's issued set and a
# forced renewal. Entry point for `task e2e:kind` and the kind CI workflow.
#
# Linux only: the cluster reaches the node over the kind docker bridge, and the
# node's http-01 fetch reaches the cluster's ingress on 127.0.0.1:80. It skips
# (exit 0) when docker or the pinned kind cannot be had, and fails on anything
# else, including a checksum mismatch.
#
# Needs: docker, curl, sha256sum, go, and sudo for one /etc/hosts line (added
# and removed by this script). KEEP_CLUSTER=1 leaves the cluster up afterwards.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
# shellcheck source=test/kind/versions.env
source "$here/versions.env"

cluster="${CRYPTOS_E2E_KIND_CLUSTER:-cryptos-e2e}"
hostname="whoami.cryptos.test"
hosts_marker="# cryptos-e2e-kind"
cache="${XDG_CACHE_HOME:-$HOME/.cache}/cryptos-e2e-kind"
work="$(mktemp -d)"
kubeconfig="$work/kubeconfig"

log() { printf '[e2e:kind] %s\n' "$*" >&2; }
skip() {
  log "SKIP: $*"
  exit 0
}

# ---- preflight -------------------------------------------------------------

[ "$(uname -s)" = "Linux" ] || skip "needs a Linux host (the cluster reaches the node over the docker bridge); this is $(uname -s)"
command -v docker >/dev/null 2>&1 || skip "docker is not installed"
docker info >/dev/null 2>&1 || skip "the docker daemon is not reachable (is it running, and can this user use it?)"
for tool in curl sha256sum go; do
  command -v "$tool" >/dev/null 2>&1 || { log "missing required tool: $tool"; exit 1; }
done

case "$(uname -m)" in
  x86_64) arch=amd64 kind_sha="$KIND_SHA256_AMD64" kubectl_sha="$KUBECTL_SHA256_AMD64" ;;
  aarch64 | arm64) arch=arm64 kind_sha="$KIND_SHA256_ARM64" kubectl_sha="$KUBECTL_SHA256_ARM64" ;;
  *) skip "no pinned kind/kubectl for $(uname -m)" ;;
esac

# fetch downloads url to dest unless dest already matches sha. A failed download
# returns 2 so the caller can decide between skipping and failing; a checksum
# mismatch is always fatal.
fetch() {
  local url="$1" dest="$2" sha="$3"
  if [ -f "$dest" ] && echo "$sha  $dest" | sha256sum -c --status -; then
    log "cached: $dest"
    return 0
  fi
  log "downloading $url"
  mkdir -p "$(dirname "$dest")"
  if ! curl -fsSL --retry 3 -o "$dest.tmp" "$url"; then
    rm -f "$dest.tmp"
    return 2
  fi
  if ! echo "$sha  $dest.tmp" | sha256sum -c --status -; then
    log "checksum mismatch for $url (want $sha, got $(sha256sum "$dest.tmp" | cut -d' ' -f1))"
    rm -f "$dest.tmp"
    exit 1
  fi
  mv "$dest.tmp" "$dest"
}

kind_bin="$cache/kind-$KIND_VERSION-$arch"
fetch "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_VERSION/kind-linux-$arch" "$kind_bin" "$kind_sha" ||
  skip "kind $KIND_VERSION is not cached and could not be downloaded"
chmod +x "$kind_bin"

kubectl_bin="$cache/kubectl-$KUBECTL_VERSION-$arch"
fetch "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/$arch/kubectl" "$kubectl_bin" "$kubectl_sha" ||
  { log "kubectl $KUBECTL_VERSION could not be downloaded"; exit 1; }
chmod +x "$kubectl_bin"

cm_yaml="$cache/cert-manager-$CERT_MANAGER_VERSION.yaml"
fetch "https://github.com/cert-manager/cert-manager/releases/download/$CERT_MANAGER_VERSION/cert-manager.yaml" "$cm_yaml" "$CERT_MANAGER_SHA256" ||
  { log "cert-manager $CERT_MANAGER_VERSION manifest could not be downloaded"; exit 1; }

contour_yaml="$cache/contour-$CONTOUR_VERSION.yaml"
fetch "https://raw.githubusercontent.com/projectcontour/contour/$CONTOUR_VERSION/examples/render/contour.yaml" "$contour_yaml" "$CONTOUR_SHA256" ||
  { log "Contour $CONTOUR_VERSION manifest could not be downloaded"; exit 1; }

kind() { "$kind_bin" "$@"; }
kubectl() { "$kubectl_bin" --kubeconfig "$kubeconfig" "$@"; }

# ---- teardown --------------------------------------------------------------

added_hosts=0
cleanup() {
  local rc=$?
  if [ "$added_hosts" = 1 ]; then
    log "removing the $hostname line from /etc/hosts"
    sudo sed -i "/$hosts_marker\$/d" /etc/hosts || true
  fi
  if [ "${KEEP_CLUSTER:-0}" = 1 ]; then
    log "KEEP_CLUSTER=1: leaving cluster $cluster up (kubeconfig: $kubeconfig)"
  else
    kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
    rm -rf "$work"
  fi
  exit "$rc"
}
trap cleanup EXIT

# ---- name resolution on the host --------------------------------------------

# The node's http-01 validator resolves the name the ordinary way, so the host
# must resolve it to the ingress on loopback. No validator bypass exists, and
# none is added for this test.
if ! grep -qE "^[^#]*[[:space:]]$hostname([[:space:]]|\$)" /etc/hosts; then
  if ! sudo -n true 2>/dev/null; then
    log "add this line to /etc/hosts and rerun (sudo is needed to add it for you):"
    log "  127.0.0.1 $hostname"
    exit 1
  fi
  echo "127.0.0.1 $hostname $hosts_marker" | sudo tee -a /etc/hosts >/dev/null
  added_hosts=1
  log "added 127.0.0.1 $hostname to /etc/hosts"
fi

# ---- cluster ---------------------------------------------------------------

kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
log "creating kind cluster $cluster ($KIND_NODE_IMAGE)"
kind create cluster --name "$cluster" --image "$KIND_NODE_IMAGE" \
  --config "$here/kind-config.yaml" --kubeconfig "$kubeconfig" --wait 120s

host_ip="$(docker inspect -f '{{with index .NetworkSettings.Networks "kind"}}{{.Gateway}}{{end}}' "$cluster-control-plane")"
[ -n "$host_ip" ] || { log "could not read the kind network gateway"; exit 1; }
log "pods reach this host at $host_ip"

log "installing Contour $CONTOUR_VERSION"
kubectl apply -f "$contour_yaml" >/dev/null
log "installing cert-manager $CERT_MANAGER_VERSION"
kubectl apply -f "$cm_yaml" >/dev/null
log "deploying the whoami test app"
sed -e "s|WHOAMI_IMAGE|$WHOAMI_IMAGE|" -e "s|E2E_HOSTNAME|$hostname|g" "$here/whoami.yaml" | kubectl apply -f - >/dev/null

kubectl -n projectcontour wait --for=condition=complete job --all --timeout=180s
kubectl -n projectcontour rollout status deployment/contour --timeout=180s
kubectl -n projectcontour rollout status daemonset/envoy --timeout=180s
kubectl -n cert-manager wait --for=condition=Available deployment --all --timeout=180s
kubectl -n cryptos-e2e rollout status deployment/whoami --timeout=180s

# cert-manager checks the challenge URL from inside the cluster before it asks
# the CA to validate, so the name must resolve there too: to Envoy's service.
envoy_ip="$(kubectl -n projectcontour get service envoy -o jsonpath='{.spec.clusterIP}')"
log "CoreDNS: $hostname -> $envoy_ip (Envoy)"
corefile="$(kubectl -n kube-system get configmap coredns -o jsonpath='{.data.Corefile}')"
corefile="$(printf '%s\n' "$corefile" | awk -v ip="$envoy_ip" -v h="$hostname" '
  { print }
  /^\.:53 \{/ { print "    hosts {\n        " ip " " h "\n        fallthrough\n    }" }')"
kubectl -n kube-system create configmap coredns --from-literal=Corefile="$corefile" --dry-run=client -o yaml |
  kubectl apply -f - >/dev/null
kubectl -n kube-system rollout restart deployment/coredns >/dev/null
kubectl -n kube-system rollout status deployment/coredns --timeout=120s

# ---- the test --------------------------------------------------------------

log "running TestKindCertManagerACME"
cd "$root"
CRYPTOS_E2E_KIND=1 \
  CRYPTOS_E2E_KIND_HOST_IP="$host_ip" \
  CRYPTOS_E2E_KIND_HOSTNAME="$hostname" \
  CRYPTOS_E2E_KIND_KUBECONFIG="$kubeconfig" \
  CRYPTOS_E2E_KIND_KUBECTL="$kubectl_bin" \
  go test -count=1 -v -timeout 15m -run '^TestKindCertManagerACME$' ./internal/e2e/
