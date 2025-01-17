# K8S-PERF-0004 - Ensure CPU Requests are Set for Containers

## Description

This rule checks if CPU requests are defined for containers within Kubernetes Pods, Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, and ReplicaSets. Setting CPU requests is essential for the Kubernetes scheduler to make informed decisions about where to place pods on nodes.

## Why It Matters

-   **Resource Management:** CPU requests help the Kubernetes scheduler understand the minimum CPU resources required by your containers. This allows for efficient resource allocation and prevents resource starvation.
-   **Scheduling:** Without CPU requests, the scheduler might place pods on nodes that don't have enough available CPU, leading to performance issues.
-   **Performance:** By setting appropriate CPU requests, you can ensure your containers have the necessary CPU resources to perform well.
-   **Cost Optimization:** By specifying accurate CPU requests, you can optimize resource utilization and potentially reduce infrastructure costs.

## How to Fix

Define CPU requests for your containers within the `resources.requests` section of the container specification.

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
        cpu: "100m" # Request 100 millicores
```

## Severity

  - **Warning**

## Other Relevant Information

-   This rule checks for the presence of the `cpu` key within the `resources.requests` section of a container specification.
-   The value of the CPU request can be expressed in various units, such as "m" (millicores), "cores", or a fraction.
-   It is also recommended to set CPU limits (`resources.limits.cpu`) to prevent containers from consuming excessive CPU resources.
-   Refer to the Kubernetes documentation for more information on managing resources for containers.
