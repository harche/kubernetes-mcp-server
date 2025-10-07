package ocp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/containers/kubernetes-mcp-server/pkg/kubernetes"
	"github.com/containers/kubernetes-mcp-server/pkg/version"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/utils/ptr"
)

const (
	// DefaultNodeDebugImage is a lightweight image that provides the tooling required to run chroot.
	DefaultNodeDebugImage = "quay.io/fedora/fedora:latest"
	// NodeDebugContainerName is the name used for the debug container, matching oc debug defaults.
	NodeDebugContainerName = "debug"
	// DefaultNodeDebugTimeout is the maximum time to wait for the debug pod to finish executing.
	DefaultNodeDebugTimeout = 1 * time.Minute
)

// NodesDebugExec mimics `oc debug node/<name> -- <command...>` by creating a privileged pod on the target
// node, running the provided command within a chroot of the host filesystem, collecting its output, and
// removing the pod afterwards.
//
// When namespace is empty, the configured namespace (or "default" if none) is used. When image is empty the
// default debug image is used. Timeout controls how long we wait for the pod to complete.
func NodesDebugExec(
	ctx context.Context,
	k *kubernetes.Kubernetes,
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

	ns := namespace
	if ns == "" {
		if k != nil {
			ns = k.NamespaceOrDefault(namespace)
		}
		if ns == "" {
			ns = "default"
		}
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

	// Get typed pod client
	podClient, err := getPodClient(k, ns)
	if err != nil {
		return "", fmt.Errorf("failed to get pod client: %w", err)
	}

	// Ensure the pod is deleted regardless of completion state.
	defer func() {
		deleteCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = podClient.Delete(deleteCtx, created.Name, metav1.DeleteOptions{})
	}()

	// Poll for debug pod completion
	terminated, lastPod, waitMsg, err := pollForCompletion(ctx, podClient, created.Name, timeout)
	if err != nil {
		return "", err
	}

	// Retrieve the logs
	logs, err := retrieveLogs(ctx, podClient, created.Name)
	if err != nil {
		return "", err
	}

	// Process the results
	return processResults(terminated, lastPod, waitMsg, logs)
}

// getPodClient returns a typed Pod client for the given namespace
func getPodClient(k *kubernetes.Kubernetes, namespace string) (corev1client.PodInterface, error) {
	// Allow injection of custom pod client for testing
	if podClientFactory != nil {
		return podClientFactory(namespace)
	}

	cfg, err := k.ToRESTConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get REST config: %w", err)
	}

	clientset, err := corev1client.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create core v1 client: %w", err)
	}

	return clientset.Pods(namespace), nil
}

// podClientFactory allows injecting a custom pod client for testing
var podClientFactory func(namespace string) (corev1client.PodInterface, error)

// createDebugPod creates a privileged pod on the target node to run debug commands.
func createDebugPod(
	ctx context.Context,
	k *kubernetes.Kubernetes,
	nodeName string,
	namespace string,
	image string,
	command []string,
) (*corev1.Pod, error) {
	sanitizedNode := sanitizeForName(nodeName)
	hostPathType := corev1.HostPathDirectory

	debugPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("node-debug-%s-", sanitizedNode),
			Namespace:    namespace,
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

	// Get typed pod client and create the pod
	podClient, err := getPodClient(k, namespace)
	if err != nil {
		return nil, err
	}

	created, err := podClient.Create(ctx, debugPod, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create debug pod: %w", err)
	}

	return created, nil
}

// pollForCompletion polls the debug pod until it completes or times out.
func pollForCompletion(
	ctx context.Context,
	podClient corev1client.PodInterface,
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

		// Get pod status using typed client
		current, getErr := podClient.Get(pollCtx, podName, metav1.GetOptions{})
		if getErr != nil {
			return nil, nil, "", fmt.Errorf("failed to get debug pod status: %w", getErr)
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
func retrieveLogs(ctx context.Context, podClient corev1client.PodInterface, podName string) (string, error) {
	logCtx, logCancel := context.WithTimeout(ctx, 30*time.Second)
	defer logCancel()

	req := podClient.GetLogs(podName, &corev1.PodLogOptions{
		Container: NodeDebugContainerName,
	})

	stream, err := req.Stream(logCtx)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve debug pod logs: %w", err)
	}
	defer func() { _ = stream.Close() }()

	buf := new(strings.Builder)
	_, err = io.Copy(buf, stream)
	if err != nil {
		return "", fmt.Errorf("failed to read debug pod logs: %w", err)
	}

	return strings.TrimSpace(buf.String()), nil
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
