# K8S-PERF-0002 - Ensure Memory Requests are Set for Containers

## Description

This rule checks if memory requests are defined for containers within Kubernetes Pods, Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, and ReplicaSets. Setting memory requests is crucial for the Kubernetes scheduler to make informed decisions about where to place pods on nodes.

## Why It Matters

-   **Resource Management:** Memory requests help the Kubernetes scheduler understand the minimum memory requirements of your containers. This allows for efficient resource allocation and prevents resource starvation.
-   **Scheduling:** Without memory requests, the scheduler might place pods on nodes that don't have enough available memory, leading to performance issues or even Pod evictions.
-   **Stability:** Properly defined memory requests contribute to the overall stability of your Kubernetes cluster.
-   **Cost Optimization:** By specifying accurate memory requests, you can optimize resource utilization and potentially reduce infrastructure costs.

## How to Fix

Define memory requests for your containers within the `resources.requests` section of the container specification.

## Example

### Manifest Triggering the Rule

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  containers:
  - name: my-container
    image: my-image
```

### Corrected Manifest

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  containers:
  - name: my-container
    image: my-image
    resources:
      requests:
        memory: "64Mi" # Request 64 Mebibytes of memory
```

## Severity

  - **Info**

## Other Relevant Information

-   This rule checks for the presence of the `memory` key within the `resources.requests` section of a container specification.
-   The value of the memory request can be expressed in various units, such as `Mi` (Mebibytes), `Gi` (Gibibytes), etc.
-   It is also recommended to set memory limits (`resources.limits.memory`) to prevent containers from consuming excessive memory.
-   Refer to the Kubernetes documentation for more information on managing resources for containers.
