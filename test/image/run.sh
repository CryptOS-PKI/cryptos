#!/usr/bin/env bash
# Run the full-image suite: boot the real CryptOS image in QEMU (swtpm, OVMF)
# as a Root and an Intermediate and drive them over the mTLS API with
# cryptosctl, the way an operator would. The steps live in
# test/integration/image_suite_test.go (TestImageSuite); each one reports
# pass, fail or skip in a summary table. Entry point for `task e2e:image` and
# the ci-e2e-image workflow.
#
# This script stands up what the steps need around the VMs: a kind cluster
# with cert-manager and Contour for the ACME step (the pins in
# test/kind/versions.env), a coverage-instrumented cryptosctl, and one
# /etc/hosts line so the node's http-01 fetch, which goes through QEMU's DNS
# proxy to this host's resolver, lands on the cluster ingress. It then merges
# the coverage counters the VMs and cryptosctl wrote.
#
# Linux only. It skips (exit 0) when the host is not Linux or lacks docker,
# qemu, swtpm or OVMF, and fails on anything else. Needs: docker, curl,
# sha256sum, go, openssl, qemu-system-x86_64, swtpm, sgdisk, mtools, OVMF,
# and sudo for the /etc/hosts line (added and removed here).
#
# Environment:
#   E2E_IMAGE_UKI   the UKI to boot (default build/out/cryptos-amd64-e2e.uki;
#                   test/image/build.sh makes it)
#   E2E_OUT         where logs, the step summary and coverage go (default a
#                   temp dir, printed at the end)
#   KEEP_CLUSTER=1  leave the kind cluster up afterwards
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
# shellcheck source=test/kind/versions.env
source "$root/test/kind/versions.env"
# shellcheck source=test/image/versions.env
source "$here/versions.env"

cluster="${CRYPTOS_E2E_IMAGE_CLUSTER:-cryptos-e2e-image}"
hostname="whoami.cryptos.test"
hosts_marker="# cryptos-e2e-image"
# QEMU user networking puts the host at this address inside each VM
# (net=10.0.0.0/24,host=10.0.0.1); a guest connection to it lands on the
# host's loopback, where kind maps the ingress's ports 80 and 443.
guest_host_ip="10.0.0.1"
cache="${XDG_CACHE_HOME:-$HOME/.cache}/cryptos-e2e-kind"
uki="${E2E_IMAGE_UKI:-$root/build/out/cryptos-amd64-e2e.uki}"

log() { printf '[e2e:image] %s\n' "$*" >&2; }
skip() {
  log "SKIP: $*"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '## Full-image suite\n\nSkipped: %s\n' "$*" >>"$GITHUB_STEP_SUMMARY"
  fi
  exit 0
}

# ---- preflight -------------------------------------------------------------

[ "$(uname -s)" = "Linux" ] || skip "needs a Linux host (QEMU with KVM, docker and kind); this is $(uname -s)"
[ "$(uname -m)" = "x86_64" ] || skip "the suite boots the amd64 image; this host is $(uname -m)"
command -v docker >/dev/null 2>&1 || skip "docker is not installed"
docker info >/dev/null 2>&1 || skip "the docker daemon is not reachable (is it running, and can this user use it?)"
for tool in qemu-system-x86_64 swtpm sgdisk mformat mcopy; do
  command -v "$tool" >/dev/null 2>&1 || skip "$tool is not installed"
done
ovmf_code="${OVMF_CODE:-}"
ovmf_vars="${OVMF_VARS:-}"
for pair in /usr/share/OVMF/OVMF_CODE_4M.fd:/usr/share/OVMF/OVMF_VARS_4M.fd /usr/share/OVMF/OVMF_CODE.fd:/usr/share/OVMF/OVMF_VARS.fd /usr/share/edk2/ovmf/OVMF_CODE.fd:/usr/share/edk2/ovmf/OVMF_VARS.fd; do
  [ -n "$ovmf_code" ] && break
  if [ -f "${pair%%:*}" ] && [ -f "${pair##*:}" ]; then
    ovmf_code="${pair%%:*}" ovmf_vars="${pair##*:}"
  fi
done
[ -n "$ovmf_code" ] || skip "OVMF firmware not found (set OVMF_CODE and OVMF_VARS)"
for tool in curl sha256sum go openssl; do
  command -v "$tool" >/dev/null 2>&1 || { log "missing required tool: $tool"; exit 1; }
done
[ -f "$uki" ] || { log "missing $uki (run test/image/build.sh first)"; exit 1; }

out="${E2E_OUT:-$(mktemp -d)}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
work="$(mktemp -d)"
kubeconfig="$work/kubeconfig"

accel=tcg
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  accel=kvm
else
  log "WARNING: /dev/kvm is not usable by this user; the VMs run under TCG and every boot is much slower"
fi
log "accelerator: $accel"

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

kind_bin="$cache/kind-$KIND_VERSION-amd64"
fetch "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_VERSION/kind-linux-amd64" "$kind_bin" "$KIND_SHA256_AMD64" ||
  skip "kind $KIND_VERSION is not cached and could not be downloaded"
chmod +x "$kind_bin"
kubectl_bin="$cache/kubectl-$KUBECTL_VERSION-amd64"
fetch "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl" "$kubectl_bin" "$KUBECTL_SHA256_AMD64" ||
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
# shellcheck disable=SC2329 # run by the EXIT trap below
cleanup() {
  local rc=$?
  if [ "$added_hosts" = 1 ]; then
    log "removing the $hostname line from /etc/hosts"
    sudo sed -i "/$hosts_marker\$/d" /etc/hosts || true
  fi
  docker rm -f cryptos-e2e-nginx >/dev/null 2>&1 || true
  if [ "${KEEP_CLUSTER:-0}" = 1 ]; then
    log "KEEP_CLUSTER=1: leaving cluster $cluster up (kubeconfig: $kubeconfig)"
  else
    kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
    rm -rf "$work"
  fi
  log "logs, summary and coverage: $out"
  exit "$rc"
}
trap cleanup EXIT

# ---- name resolution for the VMs --------------------------------------------

# A VM resolves names through QEMU's DNS proxy, which asks this host's
# resolver; systemd-resolved answers from /etc/hosts. The name points at the
# host as the VM sees it, so the node's http-01 fetch reaches the ingress on
# this host's loopback. Nothing on the host itself dials the name.
if ! grep -qE "^[^#]*[[:space:]]$hostname([[:space:]]|\$)" /etc/hosts; then
  if ! sudo -n true 2>/dev/null; then
    log "add this line to /etc/hosts and rerun (sudo is needed to add it for you):"
    log "  $guest_host_ip $hostname"
    exit 1
  fi
  echo "$guest_host_ip $hostname $hosts_marker" | sudo tee -a /etc/hosts >/dev/null
  added_hosts=1
  log "added $guest_host_ip $hostname to /etc/hosts"
fi

# ---- cluster ---------------------------------------------------------------

started=$SECONDS
kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
log "creating kind cluster $cluster ($KIND_NODE_IMAGE)"
kind create cluster --name "$cluster" --image "$KIND_NODE_IMAGE" \
  --config "$root/test/kind/kind-config.yaml" --kubeconfig "$kubeconfig" --wait 120s

host_ip="$(docker inspect -f '{{with index .NetworkSettings.Networks "kind"}}{{.Gateway}}{{end}}' "$cluster-control-plane")"
[ -n "$host_ip" ] || { log "could not read the kind network gateway"; exit 1; }
log "pods reach this host at $host_ip"

kubectl apply -f "$contour_yaml" >/dev/null
kubectl apply -f "$cm_yaml" >/dev/null
sed -e "s|WHOAMI_IMAGE|$WHOAMI_IMAGE|" -e "s|E2E_HOSTNAME|$hostname|g" "$root/test/kind/whoami.yaml" | kubectl apply -f - >/dev/null
kubectl -n projectcontour wait --for=condition=complete job --all --timeout=180s
kubectl -n projectcontour rollout status deployment/contour --timeout=180s
kubectl -n projectcontour rollout status daemonset/envoy --timeout=180s
kubectl -n cert-manager wait --for=condition=Available deployment --all --timeout=180s
kubectl -n cryptos-e2e rollout status deployment/whoami --timeout=180s

envoy_ip="$(kubectl -n projectcontour get service envoy -o jsonpath='{.spec.clusterIP}')"
corefile="$(kubectl -n kube-system get configmap coredns -o jsonpath='{.data.Corefile}')"
corefile="$(printf '%s\n' "$corefile" | awk -v ip="$envoy_ip" -v h="$hostname" '
  { print }
  /^\.:53 \{/ { print "    hosts {\n        " ip " " h "\n        fallthrough\n    }" }')"
kubectl -n kube-system create configmap coredns --from-literal=Corefile="$corefile" --dry-run=client -o yaml |
  kubectl apply -f - >/dev/null
kubectl -n kube-system rollout restart deployment/coredns >/dev/null
kubectl -n kube-system rollout status deployment/coredns --timeout=120s
log "cluster ready in $((SECONDS - started))s"

docker pull -q "$NGINX_IMAGE" >/dev/null

# ---- coverage-instrumented cryptosctl ----------------------------------------

cover_dir="$out/coverage"
rm -rf "$cover_dir"
mkdir -p "$cover_dir/cryptosctl"
cryptosctl="$work/cryptosctl"
( cd "$root" && CGO_ENABLED=0 go build -trimpath -cover -covermode=atomic -coverpkg=github.com/CryptOS-PKI/cryptos-node/... \
  -ldflags "$(bash build/ci/buildinfo.sh)" -o "$cryptosctl" ./cmd/cryptosctl )

# ---- the suite ---------------------------------------------------------------

log "running TestImageSuite"
set +e
(
  cd "$root" &&
    CRYPTOS_E2E_IMAGE=1 \
      E2E_IMAGE_UKI="$uki" \
      E2E_IMAGE_NEXT_UKI="${uki%.uki}-next.uki" \
      E2E_IMAGE_ACCEL="$accel" \
      E2E_IMAGE_OUT="$out" \
      E2E_IMAGE_COVERDIR="$cover_dir" \
      OVMF_CODE="$ovmf_code" OVMF_VARS="$ovmf_vars" \
      CRYPTOSCTL="$cryptosctl" \
      E2E_IMAGE_HOST_IP="$host_ip" \
      E2E_IMAGE_HOSTNAME="$hostname" \
      E2E_IMAGE_KUBECONFIG="$kubeconfig" \
      E2E_IMAGE_KUBECTL="$kubectl_bin" \
      E2E_IMAGE_NGINX="$NGINX_IMAGE" \
      go test -tags=integration -count=1 -v -timeout 35m -run '^TestImageSuite$' ./test/integration/
) 2>&1 | tee "$out/suite.log"
rc=${PIPESTATUS[0]}
set -e

# ---- coverage ------------------------------------------------------------------

bash "$here/coverage.sh" "$cover_dir" "$out" || log "coverage report failed (the suite result stands)"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  [ -f "$out/summary.md" ] && cat "$out/summary.md" >>"$GITHUB_STEP_SUMMARY"
  [ -f "$out/coverage-summary.md" ] && cat "$out/coverage-summary.md" >>"$GITHUB_STEP_SUMMARY"
fi
exit "$rc"
