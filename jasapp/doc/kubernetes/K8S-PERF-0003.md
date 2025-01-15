# K8S-PERF-0003 - Ensure Memory Limits are Set for Containers

## Description

This rule checks if memory limits are defined for containers within Kubernetes Pods, Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, and ReplicaSets. Setting memory limits prevents containers from consuming excessive memory resources on the node, which can impact other containers or the stability of the node itself. Memory limits also help prevent the `kubelet` from making incorrect decisions when calculating memory usage.

## Why It Matters

-   **Resource Management:** Memory limits ensure that containers don't use more memory than expected. This helps avoid resource exhaustion.
-   **Performance:** By setting appropriate memory limits, you can prevent memory starvation for other containers and ensure predictable performance for your applications.
-   **Stability:** Prevents containers from consuming too much memory, which could lead to node instability or Out Of Memory errors.
-   **Cost Optimization:** Helps optimize resource utilization, potentially reducing infrastructure costs.
-   **Kubelet Scheduling:** The kubelet considers resource limits when making scheduling decisions and calculating memory usage. Without limits, the kubelet may make suboptimal choices.

## How to Fix

Define memory limits for your containers within the `resources.limits` section of the container specification.

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
      limits:
        memory: "128Mi" # Limit to 128 Mebibytes of memory
```

## Severity

  - **Low**

## Other Relevant Information

-   This rule checks for the presence of the `memory` key within the `resources.limits` section of a container specification.
-   The value of the memory limit can be expressed in various units, such as `Mi` (Mebibytes), `Gi` (Gibibytes), etc.
-   It is also recommended to set memory requests (`resources.requests.memory`) to specify the minimum amount of memory resources required by the container.
-   Refer to the Kubernetes documentation for more information on managing resources for containers.
