---
authors: Andrew LeFevre (andrew.lefevre@goteleport.com)
state: draft
---

# RFD 98 - Registered OpenSSH Nodes

## Required approvers

* Engineering: @jakule && @r0mant
* Product: @klizhentas
* Security: @reedloden

## What

Allow OpenSSH nodes to be registered in a Teleport cluster.

## Why

[Agentless EC2 discovery mode](https://github.com/gravitational/teleport/issues/17865) will discover and configure OpenSSH nodes so they can authenticate with a cluster. But those OpenSSH nodes aren't registered as `node` resources in the backend. We need a way to register agentless OpenSSH nodes as `node` resources so they can be viewed and managed by users. RBAC and session recording should function correctly with registered OpenSSH nodes as well.

## Details

### Registering nodes

A new sub-kind to the `node` resource will be added for registered OpenSSH nodes: `agentless`. The absence of a `node` resource sub-kind will imply that a node is a Teleport agent node, making this change backwards compatible.

#### Registering with `tctl`

`tctl` should not require as many fields to be set when creating nodes. This is an example `node` resource that will work with `tctl create --force` today:

```yaml
kind: node
metadata:
  name: 5da56852-2adb-4540-a37c-80790203f6a9
spec:
  addr: 1.2.3.4:22
  hostname: agentless-node
version: v2
```

`tctl` will auto-generate `metadata.name` if it is not already set so users don't have to generate GUIDs themselves if `sub_kind` is `agentless`. Also, if `sub_kind` is set to `agentless`, `spec.public_addr` will not be allowed for registered OpenSSH nodes as it is not needed.

### Agentless CA

For security related reasons that will be discussed below, a new CA will be added called Agentless CA. The Agentless CA will be responsible for generating and signing user certificates that will be used to authenticate with registered OpenSSH nodes. The public key of the Agentless CA will be copied to all registered OpenSSH nodes and configured as `TrustedUserCAKeys` in `sshd_config`.

### RBAC

When OpenSSH nodes are registered currently, RBAC checks for those nodes are not performed. RBAC logic will have to be updated so RBAC checks for registered OpenSSH nodes are performed. There are multiple ways to implement this, each with their own advantages and disadvantages.

#### Option 1

Each registered OpenSSH node will have a unique Agentless CA. The CA public key will include information about the node that it was created for, including the node's UUID and the node's labels. When `(lib/srv.AuthHandlers).UserKeyAuth` is called to authenticate a node's user certificate, it will check if node information is present in the CA public key. If node information is present, an RBAC check will be performed using the label information in the CA public key.

Pros:

- No need to lookup node resources to perform RBAC checks

Cons:

- Requires connecting to node to perform RBAC check
- Updating node labels requires generating and distributing a new host key
- CA rotation is more complex as every registered OpenSSH node requires a unique CA

#### Option 2

When a user sends a request to a Proxy to connect to a node, the Proxy will attempt to find a node resource by either its hostname or IP, whichever the user specified. If the resource exists and has the `agentless` `sub_kind`, an RBAC check will be performed. If the resource does not exist or isn't an `agentless` node, the connection flow will continue as normal.

Pros:

- No need to connect to node to perform RBAC check
- Updating node labels can simply be done by using `tctl`
- CA rotation is simple as every registered OpenSSH node will have the same CA

Cons: none (that I can think of)

#### My choice: Option 2

Option 2 makes CA rotation and updating node labels much easier, and has the only downside of having to search for node resources before connecting to one. 

### Security

Both RBAC checks and session recording for registered OpenSSH nodes require that users connect through a Proxy. If users are able to connect to registered OpenSSH nodes directly, they can bypass both features. Currently the User CA public key is copied to OpenSSH nodes and configured to be trusted by `sshd`. This means OpenSSH nodes will accept certificates that are signed by the User CA. The problem with that is when Teleport users authenticate with a cluster, the Auth server replies with a certificate that is signed by the User CA. Users could potentially use this certificate to directly connect to registered OpenSSH nodes.

Using the new Agentless CA to sign certificates used to authenticate with registered OpenSSH nodes solves this problem, as Teleport users do not have access to any certificates signed by the Agentless CA.

### UX

The following Teleport node features won't work with registered OpenSSH nodes:

- Enhanced session recording and restricted networking
- Host user provisioning
- Session recording without SSH session termination
- Dynamic labels
- Outbound persistent tunnels to Proxies

Due to this and other potential future differences, `tsh ls` and the node listing on the web UI should be updated to display if nodes are registered OpenSSH nodes, or simply 'agentless'.

### Future work

#### Session recording

Currently session recording is required to be set be in `proxy` mode to work with OpenSSH nodes. That is not going to change, but ideally this requirement could be lifted when Teleport agent nodes and registered OpenSSH nodes are both in a single cluster. When establishing an SSH connection inside a cluster, depending on what the session recording mode is set to the appropriate type of session recording would be used:

If session recording is in `node` or `node-sync` mode:

- If the node is a Teleport Agent node, the node would record the session and upload it as normal.
- If the node is a registered OpenSSH node, the Proxy would terminate and record the SSH session and upload it.

If session recording is in `proxy` or `proxy-sync` mode:

- Behavior would be unaffected. The Proxy would terminate, record and upload the session. This mode will still be required if users of a cluster wish to connect to unregistered OpenSSH nodes.
