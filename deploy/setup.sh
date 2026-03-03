#!/usr/bin/env bash
# Setup script for the kubernetes-mcp-server sandbox feature.
# Installs agent-sandbox CRDs/controller and applies sandbox RBAC.
#
# Usage: ./deploy/setup.sh [AGENT_SANDBOX_VERSION]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="${1:-v0.1.1}"

echo "==> Installing agent-sandbox CRDs and controller (${VERSION})..."
kubectl apply -f "https://github.com/kubernetes-sigs/agent-sandbox/releases/download/${VERSION}/manifest.yaml"

echo "==> Waiting for agent-sandbox controller to be ready..."
kubectl rollout status statefulset/agent-sandbox-controller -n agent-sandbox-system --timeout=120s

echo "==> Applying sandbox RBAC..."
kubectl apply -f "${SCRIPT_DIR}/sandbox-rbac.yaml"

echo "==> Done. Verify with:"
echo "    kubectl api-resources | grep sandbox"
echo "    kubectl get statefulset -n agent-sandbox-system"
