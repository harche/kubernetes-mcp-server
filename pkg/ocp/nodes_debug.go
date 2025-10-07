package ocp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/containers/kubernetes-mcp-server/pkg/kubernetes"
	"github.com/containers/kubernetes-mcp-server/pkg/version"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"
)

const (
	// DefaultNodeDebugImage is a lightweight image that provides the tooling required to run chroot.
	DefaultNodeDebugImage = "quay.io/fedora/fedora:latest"
	// NodeDebugContainerName is the name used for the debug container, matching oc debug defaults.
	NodeDebugContainerName = "debug"
	// DefaultNodeDebugTimeout is the maximum time to wait for the debug pod to finish executing.
	DefaultNodeDebugTimeout = 1 * time.Minute
)

// KubernetesClient defines the interface needed for node debug operations.
type KubernetesClient interface {
	NamespaceOrDefault(namespace string) string
	ResourcesCreateOrUpdate(ctx context.Context, resource string) ([]*unstructured.Unstructured, error)
	ResourcesGet(ctx context.Context, gvk *schema.GroupVersionKind, namespace, name string) (*unstructured.Unstructured, error)
	ResourcesDelete(ctx context.Context, gvk *schema.GroupVersionKind, namespace, name string) error
	PodsLog(ctx context.Context, namespace, name, container string, previous bool, tail int64) (string, error)
}

// NodesDebugExec mimics `oc debug node/<name> -- <command...>` by creating a privileged pod on the target
// node, running the provided command within a chroot of the host filesystem, collecting its output, and
// removing the pod afterwards.
//
// When namespace is empty, the configured namespace (or "default" if none) is used. When image is empty the
// default debug image is used. Timeout controls how long we wait for the pod to complete.
func NodesDebugExec(
	ctx context.Context,
	k KubernetesClient,
	namespace string,
	nodeName string,
	image string,
	command []string,
	timeout time.Duration,
) (string, error) {
	if nodeName == "" {
		return "", errors.New("node name is required")
	}
	if len(command) == 0 {
		return "", errors.New("command is required")
	}

	ns := k.NamespaceOrDefault(namespace)
	if ns == "" {
		ns = "default"
	}
	debugImage := image
	if debugImage == "" {
		debugImage = DefaultNodeDebugImage
	}
	if timeout <= 0 {
		timeout = DefaultNodeDebugTimeout
	}

	// Create the debug pod
	created, err := createDebugPod(ctx, k, nodeName, ns, debugImage, command)
	if err != nil {
		return "", err
	}

	// Ensure the pod is deleted regardless of completion state.
	defer func() {
		deleteCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = k.ResourcesDelete(deleteCtx, &podGVK, ns, created.Name)
	}()

	// Poll for debug pod completion
	terminated, lastPod, waitMsg, err := pollForCompletion(ctx, k, ns, created.Name, timeout)
	if err != nil {
		return "", err
	}

	// Retrieve the logs
	logs, err := retrieveLogs(ctx, k, ns, created.Name)
	if err != nil {
		return "", err
	}

	// Process the results
	return processResults(terminated, lastPod, waitMsg, logs)
}

// createDebugPod creates a privileged pod on the target node to run debug commands.
func createDebugPod(
	ctx context.Context,
	k KubernetesClient,
	nodeName string,
	namespace string,
	image string,
	command []string,
) (*corev1.Pod, error) {
	sanitizedNode := sanitizeForName(nodeName)
	hostPathType := corev1.HostPathDirectory

	// Generate a unique name since ResourcesCreateOrUpdate doesn't support GenerateName
	podName := fmt.Sprintf("node-debug-%s-%d", sanitizedNode, time.Now().UnixNano())

	debugPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
			Labels: map[string]string{
				kubernetes.AppKubernetesManagedBy: version.BinaryName,
				kubernetes.AppKubernetesComponent: "node-debug",
				kubernetes.AppKubernetesName:      fmt.Sprintf("node-debug-%s", sanitizedNode),
			},
		},
		Spec: corev1.PodSpec{
			AutomountServiceAccountToken: ptr.To(false),
			NodeName:                     nodeName,
			RestartPolicy:                corev1.RestartPolicyNever,
			SecurityContext: &corev1.PodSecurityContext{
				RunAsUser: ptr.To[int64](0),
			},
			Tolerations: []corev1.Toleration{
				{Operator: corev1.TolerationOpExists},
				{Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
				{Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute},
			},
			Volumes: []corev1.Volume{
				{
					Name: "host-root",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/",
							Type: &hostPathType,
						},
					},
				},
			},
			Containers: []corev1.Container{
				{
					Name:            NodeDebugContainerName,
					Image:           image,
					ImagePullPolicy: corev1.PullIfNotPresent,
					Command:         append([]string{"chroot", "/host"}, command...),
					SecurityContext: &corev1.SecurityContext{
						Privileged: ptr.To(true),
						RunAsUser:  ptr.To[int64](0),
					},
					VolumeMounts: []corev1.VolumeMount{
						{Name: "host-root", MountPath: "/host"},
					},
				},
			},
		},
	}

	// Convert Pod to YAML for ResourcesCreateOrUpdate
	debugPod.TypeMeta = metav1.TypeMeta{
		APIVersion: "v1",
		Kind:       "Pod",
	}
	podYAML, err := yaml.Marshal(debugPod)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pod to YAML: %w", err)
	}

	// Create the pod using the high-level API
	createdList, err := k.ResourcesCreateOrUpdate(ctx, string(podYAML))
	if err != nil {
		return nil, fmt.Errorf("failed to create debug pod: %w", err)
	}

	if len(createdList) == 0 {
		return nil, fmt.Errorf("ResourcesCreateOrUpdate returned empty result")
	}
	if len(createdList) != 1 {
		return nil, fmt.Errorf("expected 1 pod to be created, got %d", len(createdList))
	}
	if createdList[0] == nil {
		return nil, fmt.Errorf("ResourcesCreateOrUpdate returned nil pod")
	}

	// Convert back to typed Pod
	pod, err := unstructuredToPod(createdList[0])
	if err != nil {
		return nil, fmt.Errorf("failed to convert created pod: %w", err)
	}
	return pod, nil
}

// pollForCompletion polls the debug pod until it completes or times out.
func pollForCompletion(
	ctx context.Context,
	k KubernetesClient,
	namespace string,
	podName string,
	timeout time.Duration,
) (*corev1.ContainerStateTerminated, *corev1.Pod, string, error) {
	pollCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var (
		lastPod    *corev1.Pod
		terminated *corev1.ContainerStateTerminated
		waitMsg    string
	)

	for {
		select {
		case <-pollCtx.Done():
			return nil, nil, "", fmt.Errorf("timed out waiting for debug pod %s to complete: %w", podName, pollCtx.Err())
		default:
		}

		// Get pod status using the high-level API
		unstructuredPod, getErr := k.ResourcesGet(pollCtx, &podGVK, namespace, podName)
		if getErr != nil {
			return nil, nil, "", fmt.Errorf("failed to get debug pod status: %w", getErr)
		}

		current, err := unstructuredToPod(unstructuredPod)
		if err != nil {
			return nil, nil, "", err
		}
		lastPod = current

		if status := containerStatusByName(current.Status.ContainerStatuses, NodeDebugContainerName); status != nil {
			if status.State.Waiting != nil {
				waitMsg = fmt.Sprintf("container waiting: %s", status.State.Waiting.Reason)
				// Image pull issues should fail fast.
				if status.State.Waiting.Reason == "ErrImagePull" || status.State.Waiting.Reason == "ImagePullBackOff" {
					return nil, nil, "", fmt.Errorf("debug container failed to start (%s): %s", status.State.Waiting.Reason, status.State.Waiting.Message)
				}
			}
			if status.State.Terminated != nil {
				terminated = status.State.Terminated
				break
			}
		}

		if current.Status.Phase == corev1.PodFailed {
			break
		}

		select {
		case <-pollCtx.Done():
			return nil, nil, "", fmt.Errorf("timed out waiting for debug pod %s to complete: %w", podName, pollCtx.Err())
		case <-ticker.C:
		}
	}

	return terminated, lastPod, waitMsg, nil
}

// retrieveLogs retrieves the logs from the debug pod.
func retrieveLogs(ctx context.Context, k KubernetesClient, namespace, podName string) (string, error) {
	logCtx, logCancel := context.WithTimeout(ctx, 30*time.Second)
	defer logCancel()
	logs, logErr := k.PodsLog(logCtx, namespace, podName, NodeDebugContainerName, false, 0)
	if logErr != nil {
		return "", fmt.Errorf("failed to retrieve debug pod logs: %w", logErr)
	}
	return strings.TrimSpace(logs), nil
}

// processResults processes the debug pod completion status and returns the appropriate result.
func processResults(terminated *corev1.ContainerStateTerminated, lastPod *corev1.Pod, waitMsg, logs string) (string, error) {
	if terminated != nil {
		if terminated.ExitCode != 0 {
			errMsg := fmt.Sprintf("command exited with code %d", terminated.ExitCode)
			if terminated.Reason != "" {
				errMsg = fmt.Sprintf("%s (%s)", errMsg, terminated.Reason)
			}
			if terminated.Message != "" {
				errMsg = fmt.Sprintf("%s: %s", errMsg, terminated.Message)
			}
			return logs, errors.New(errMsg)
		}
		return logs, nil
	}

	if lastPod != nil && lastPod.Status.Reason != "" {
		return logs, fmt.Errorf("debug pod failed: %s", lastPod.Status.Reason)
	}
	if waitMsg != "" {
		return logs, fmt.Errorf("debug container did not complete: %s", waitMsg)
	}
	return logs, errors.New("debug container did not reach a terminal state")
}

func sanitizeForName(name string) string {
	lower := strings.ToLower(name)
	var b strings.Builder
	b.Grow(len(lower))
	for _, r := range lower {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
			continue
		}
		b.WriteRune('-')
	}
	sanitized := strings.Trim(b.String(), "-")
	if sanitized == "" {
		sanitized = "node"
	}
	if len(sanitized) > 40 {
		sanitized = sanitized[:40]
	}
	return sanitized
}

func containerStatusByName(statuses []corev1.ContainerStatus, name string) *corev1.ContainerStatus {
	for idx := range statuses {
		if statuses[idx].Name == name {
			return &statuses[idx]
		}
	}
	return nil
}

// unstructuredToPod converts an unstructured object to a typed Pod.
func unstructuredToPod(obj *unstructured.Unstructured) (*corev1.Pod, error) {
	pod := &corev1.Pod{}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, pod)
	if err != nil {
		return nil, fmt.Errorf("failed to convert unstructured to Pod: %w", err)
	}
	return pod, nil
}

var podGVK = schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"}
