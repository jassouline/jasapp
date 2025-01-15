# K8S-PERF-0001 - Ensure CPU Limits are Set for Containers

## Description

This rule checks if CPU limits are defined for containers within Kubernetes Pods, Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, and ReplicaSets. Setting CPU limits prevents containers from consuming excessive CPU resources on the node, which can impact other containers or the stability of the node itself.

## Why It Matters

-   **Resource Management:** CPU limits ensure fair resource allocation among containers and prevent any single container from monopolizing CPU resources.
-   **Performance:** By setting appropriate CPU limits, you can prevent CPU starvation for other containers and ensure predictable performance for your applications.
-   **Stability:** Prevents containers from consuming too much CPU, which could lead to node instability.
-   **Cost Optimization:**  Helps optimize resource utilization, potentially reducing infrastructure costs.

## How to Fix

Define CPU limits for your containers within the `resources.limits` section of the container specification.

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
        cpu: "100m" # Limit to 100 millicores
```

## Severity

  - **Low**

## Other Relevant Information

-   This rule checks for the presence of the `cpu` key within the `resources.limits` section of a container specification.
-   The value of the CPU limit can be expressed in various units, such as "m" (millicores), "cores", or a fraction.
-   It is also recommended to set CPU requests (`resources.requests.cpu`) to specify the minimum amount of CPU resources required by the container.
-   Refer to the Kubernetes documentation for more information on managing resources for containers.
