# Debugging

Follow the [Quickstart](#quickstart) guide to start and debug NGINX Ingress Controller in a local [Kind](https://kind.sigs.k8s.io/) cluster or read the [walkthrough](#debug-configuration-walkthrough) to step through the full process of configuring an environment.

Parts of these instructions assume you develop using [Visual Studio Code](https://code.visualstudio.com/), but can be modified and followed for any IDE (Integrated Development Environment).

- [Quickstart](#quickstart)
- [Debug configuration walkthrough](#debug-configuration-walkthrough)
  - [1. Build a debug container image](#1-build-a-debug-container-image)
  - [2. Deploy the debug container](#2-deploy-the-debug-container)
  - [3. Connect your debugger](#3-connect-your-debugger)
- [Helm configuration options](#helm-configuration-options)



## Quickstart

1. Set the local variables:
    ```shell
    export TARGET=debug
    export PREFIX=local/nic-debian
    export TAG=debug
    export ARCH=arm64
    ```
    NOTE: `ARCH` should be set to `amd64` or `arm64` to match your CPU architecture or debugging will not work as expected.
2. Create a local Kind cluster:
    ```shell
    make -f tests/Makefile create-kind-cluster
    ```
3. Build the NGINX Ingress Controller debug image:
    ```shell
    make debian-image
    ```
4. Load the debug image into the Kind cluster:
    ```shell
    make -f tests/Makefile image-load
    ```
5. Use the Helm chart to install NGINX Ingress Controller
    ```shell
    helm upgrade --install my-release charts/nginx-ingress -f - <<EOF
    controller:
        debug:
            enable: true
        kind: daemonset
        service:
            type: NodePort
            customPorts:
              - name: godebug
                nodePort: 32345
                port: 2345
                protocol: TCP
                targetPort: 2345
        customPorts:
          - name: godebug
            containerPort: 2345
            protocol: TCP
        readyStatus:
            enable: false
        image:
            tag: debug
            repository: local/nic-debian
    EOF
    ```
6. Add this launch configuration to the `configurations` section of your VSCode `.vscode/launch.json` file or IDE equivalent.
    ```json
    {
        "name": "Debug NGINX Ingress Controller in local Kind cluster",
        "type": "go",
        "request": "attach",
        "mode": "remote",
        "remotePath": "",
        "port":32345,
        "host":"localhost",
        "showLog": true,
        "cwd": "${workspaceFolder}"
    }
    ```
7. Run the configuration from the `Run and Debug` menu, set breakpoints, and start debugging.


## Debug configuration walkthrough

### 1. Build a debug container image

Create an NGINX Ingress Controller container with either:
1. `make <image name> TARGET=debug`
This option creates the debug NGINX Ingress Controller binary locally , then loads it into the container image.
1. `make <image name> TARGET=debug-container`
This options builds the debug NGINX Ingress Controller binary directly inside the container image.

The debug NGINX Ingress Controller binary contains debug symbols and has [Delve](https://github.com/go-delve/delve) installed. It uses `/dlv` as its entrypoint.

The following example builds a Debian image with NGINX Plus on ARM64,  tagged as `local/nic-debian-plus:debug`:

```shell
make debian-image-plus TARGET=debug PREFIX=local/nic-debian-plus TAG=debug ARCH=arm64
...
...
 => => naming to docker.io/local/nic-debian-plus:debug
```

### 2. Deploy the debug container

Use Helm to enable the debug configuration:

```yaml
controller:
    debug:
        enable: true
    service:
        type: NodePort
        customPorts:
        # only required if you want to connect
        # directly to your cluster instead of using kubectl port-forward
          - name: godebug
            nodePort: 32345
            port: 2345
            protocol: TCP
            targetPort: 2345
    customPorts:
      - name: godebug
        containerPort: 2345
        protocol: TCP
    readyStatus:
    # We recommend deactivating readinessProbes while debugging
    # to ensure upgrades and service connections run as expected
        enable: false
    image:
        tag: debug
        repository: local/nic-debian-plus
```

If you are not using Helm, manually add the Delve CLI arguments to the deployment or daemonset:
```yaml
args:
- --listen=:2345
- --headless=true
- --log=true
- --log-output=debugger,debuglineerr,gdbwire,lldbout,rpc,dap,fncall,minidump,stack
- --accept-multiclient
- --api-version=2
- exec
- ./nginx-ingress
- --continue
- --
<regular NGINX Ingress Controller CLI configuration>
```

Delve will immediately start NGINX Ingress Controller by default. To prevent this, set `controller.debug.continue: false.`  Delve will then wait for a debugger to connect before starting NGINX Ingress Controller, which is useful for observing start-up behaviour.

### 3. Connect your debugger

Connect to the remote Delve API server through your IDE:
- [JetBrains](https://www.jetbrains.com/help/go/attach-to-running-go-processes-with-debugger.html)
- [VSCode](https://github.com/golang/vscode-go/blob/master/docs/debugging.md)

Example VSCode configuration:

```json
{
    "name": "Debug NIC",
    "type": "go",
    "request": "attach",
    "mode": "remote",
    "remotePath": "",
    "port":32345,
    "host":"<cluster where nodeport is exposed, or localhost if using kubectl port forward>",
    "showLog": true,
    "cwd": "${workspaceFolder}"
}
```

You may want to expose the debug port of your cluster via `kubectl port-forward` :
```shell
kubectl port-forward my-release-nginx-ingress-controller-z48wf 32345:2345
```

## Helm configuration options

| Parameter                   | Description                                                                                                   | Default |
| --------------------------- | ------------------------------------------------------------------------------------------------------------- | ------- |
| `controller.debug.enable`   | Injects Delve CLI parameters into the `args` configuration of the NIC container.                              | `false` |
| `controller.debug.continue` | Sets the `--continue` Delve flag which continues the NIC process instead of waiting for a debugger to attach. | `true`  |
