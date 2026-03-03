package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/containers/kubernetes-mcp-server/pkg/version"
)

const SandboxComponent = "shell-sandbox"

var SandboxPartOf = version.BinaryName + "-shell-sandbox"

// SandboxOptions contains the options for creating a sandbox pod.
type SandboxOptions struct {
	Name               string
	Namespace          string
	Image              string
	ServiceAccountName string
	CPURequest         string
	CPULimit           string
	MemoryRequest      string
	MemoryLimit        string
}

// SandboxDefaultName generates a default sandbox pod name.
func SandboxDefaultName() string {
	return version.BinaryName + "-sandbox-" + rand.String(5)
}

// sandboxGVR is the GroupVersionResource for the agent-sandbox Sandbox CRD.
var sandboxGVR = schema.GroupVersionResource{
	Group:    "agents.x-k8s.io",
	Version:  "v1alpha1",
	Resource: "sandboxes",
}

// SandboxCreate creates a Sandbox CR (agents.x-k8s.io/v1alpha1) and its ServiceAccount.
// The agent-sandbox controller manages the pod lifecycle.
// Returns the created resources as unstructured objects.
func (c *Core) SandboxCreate(ctx context.Context, opts SandboxOptions) ([]*unstructured.Unstructured, error) {
	namespace := c.NamespaceOrDefault(opts.Namespace)
	labels := map[string]string{
		AppKubernetesName:      opts.Name,
		AppKubernetesComponent: SandboxComponent,
		AppKubernetesManagedBy: version.BinaryName,
		AppKubernetesPartOf:    SandboxPartOf,
	}

	// ServiceAccount (not managed by agent-sandbox controller, created separately)
	sa := &v1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"},
		ObjectMeta: metav1.ObjectMeta{Name: opts.ServiceAccountName, Namespace: namespace, Labels: labels},
	}
	converter := runtime.DefaultUnstructuredConverter
	saMap, err := converter.ToUnstructured(sa)
	if err != nil {
		return nil, fmt.Errorf("failed to convert ServiceAccount to unstructured: %w", err)
	}
	saUnstructured := &unstructured.Unstructured{Object: saMap}

	// Sandbox CR — the agent-sandbox controller creates the pod with the same name
	sandbox := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "agents.x-k8s.io/v1alpha1",
			"kind":       "Sandbox",
			"metadata": map[string]interface{}{
				"name":      opts.Name,
				"namespace": namespace,
				"labels": map[string]interface{}{
					AppKubernetesName:      opts.Name,
					AppKubernetesComponent: SandboxComponent,
					AppKubernetesManagedBy: version.BinaryName,
					AppKubernetesPartOf:    SandboxPartOf,
				},
			},
			"spec": map[string]interface{}{
				"podTemplate": map[string]interface{}{
					"spec": map[string]interface{}{
						"serviceAccountName": opts.ServiceAccountName,
						"restartPolicy":      "Never",
						"containers": []interface{}{
							map[string]interface{}{
								"name":            "sandbox",
								"image":           opts.Image,
								"imagePullPolicy": "IfNotPresent",
								"command":         []interface{}{"sleep", "infinity"},
								"resources": map[string]interface{}{
									"requests": map[string]interface{}{
										"cpu":    opts.CPURequest,
										"memory": opts.MemoryRequest,
									},
									"limits": map[string]interface{}{
										"cpu":    opts.CPULimit,
										"memory": opts.MemoryLimit,
									},
								},
								"readinessProbe": map[string]interface{}{
									"exec": map[string]interface{}{
										"command": []interface{}{"/bin/sh", "-c", "true"},
									},
									"initialDelaySeconds": int64(2),
									"periodSeconds":       int64(5),
								},
							},
						},
					},
				},
			},
		},
	}

	return c.resourcesCreateOrUpdate(ctx, []*unstructured.Unstructured{saUnstructured, sandbox})
}

// SandboxWaitReady waits for the sandbox pod to reach the Running phase.
func (c *Core) SandboxWaitReady(ctx context.Context, namespace, name string, timeout time.Duration) error {
	namespace = c.NamespaceOrDefault(namespace)
	return wait.PollUntilContextTimeout(ctx, 2*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		pod, err := c.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, nil // retry on transient errors
		}
		if pod.Status.Phase == v1.PodRunning {
			return true, nil
		}
		if pod.Status.Phase == v1.PodFailed || pod.Status.Phase == v1.PodSucceeded {
			return false, fmt.Errorf("sandbox pod %s/%s terminated with phase %s", namespace, name, pod.Status.Phase)
		}
		return false, nil
	})
}

// SandboxExec executes a shell command in the sandbox pod.
// The command is wrapped in bash -c for shell interpretation (pipes, redirects, etc.).
func (c *Core) SandboxExec(ctx context.Context, namespace, name, command string) (string, error) {
	return c.PodsExec(ctx, namespace, name, "sandbox", []string{"/bin/bash", "-c", command})
}

// SandboxStatus returns the pod object for a sandbox.
func (c *Core) SandboxStatus(ctx context.Context, namespace, name string) (*v1.Pod, error) {
	namespace = c.NamespaceOrDefault(namespace)
	return c.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
}

// SandboxDestroy deletes the Sandbox CR (which cascades to the pod and headless service)
// and the associated ServiceAccount.
func (c *Core) SandboxDestroy(ctx context.Context, namespace, name, serviceAccountName string) error {
	namespace = c.NamespaceOrDefault(namespace)
	var errs []error

	// Delete the Sandbox CR — the controller cascades deletion to the pod and service
	if err := c.DynamicClient().Resource(sandboxGVR).Namespace(namespace).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		errs = append(errs, fmt.Errorf("sandbox %s: %w", name, err))
	}

	// Delete the ServiceAccount separately (not managed by the agent-sandbox controller)
	if serviceAccountName != "" {
		if err := c.CoreV1().ServiceAccounts(namespace).Delete(ctx, serviceAccountName, metav1.DeleteOptions{}); err != nil {
			errs = append(errs, fmt.Errorf("serviceaccount %s: %w", serviceAccountName, err))
		}
	}

	return errors.Join(errs...)
}
