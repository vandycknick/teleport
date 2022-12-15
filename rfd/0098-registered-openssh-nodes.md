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

### OpenSSH CA

For security related reasons that will be discussed below, a new CA will be added called OpenSSH CA. The OpenSSH CA will be responsible for generating and signing user certificates that will be used to authenticate with registered OpenSSH nodes. The OpenSSH CA will not be used to generate certificates for existing or future *unregistered* OpenSSH nodes, preserving backwards compatibility for existing OpenSSH nodes.

### RBAC

When OpenSSH nodes are registered currently, RBAC checks for those nodes are not preformed. Even setting `auth_service.session_recording` to `proxy` in an Auth Server's config file does not help. RBAC logic will have to be updated so RBAC checks for registered OpenSSH nodes are preformed.

When `(lib/srv.AuthHandlers).UserKeyAuth` is called to authenticate a node's user certificate, it will check what CA signed the certificate. If the OpenSSH CA signed the certificate, the node will be recognized as a registered OpenSSH node. `UserKeyAuth` will lookup the node's details and preform an RBAC check.

### Registering nodes

A new sub-kind to the `node` resource will be added for registered OpenSSH nodes: `openssh`. The absence of a `node` resource sub-kind will imply that a node is a Teleport agent node, making this change backwards compatible.

#### Registering with `tctl`

OpenSSH nodes can already be manually registered using `tctl create --force /path/to/node.yml`, though some changes should be made to make the process more straightforward for users. Agentless EC2 discovery mode will registered discovered OpenSSH nodes without needing user intervention, but if automatically registering an OpenSSH node fails a user may want to register a node manually. Currently nodes cannot be created with `tctl`, only upserted. This limitation should be removed so users can create nodes without having to pass `--force` to `tctl create`.

Furthermore, `tctl` should not require as many fields to be set when creating nodes. This is an example `node` resource that will work with `tctl create` today:

```yaml
kind: node
metadata:
  name: 5da56852-2adb-4540-a37c-80790203f6a9
spec:
  addr: 1.2.3.4:22
  hostname: agentless-node
version: v2
```

`tctl create` will auto-generate `metadata.name` if it is not already set so users don't have to generate GUIDs themselves. Also, if `sub_kind` is set to `openssh`, `spec.public_addr` will not be allowed for registered OpenSSH nodes as it is not needed.

### Session recording

Currently session recording is required to be set be in `proxy` mode to work with OpenSSH nodes. That is not going to change, but ideally this requirement could be lifted when Teleport agent nodes and registered OpenSSH nodes are both in a single cluster. When establishing an SSH connection inside a cluster, depending on what the session recording mode is set to the appropriate type of session recording would be used:

If session recording is in `node` or `node-sync` mode:

- If the node is a Teleport Agent node, the node would record the session and upload it as normal.
- If the node is a registered OpenSSH node, the Proxy would terminate and record the SSH session and upload it.

If session recording is in `proxy` or `proxy-sync` mode:

- Behavior would be unaffected. The Proxy would terminate, record and upload the session. This mode will still be required if users of a cluster wish to connect to unregistered OpenSSH nodes.

I propose that `proxy` or `proxy-sync` session recording modes continue to be required when connecting to any OpenSSH node through Teleport, *at first*. When registering OpenSSH nodes and preforming RBAC checks on them is completed and possibly released, then work could be done to streamline session recording with registered OpenSSH nodes.

### Security

Both RBAC checks and session recording for registered OpenSSH nodes require that users connect through a Proxy. If users are able to connect to registered OpenSSH nodes directly, they can bypass both features. Currently the User CA public key is copied to OpenSSH nodes and configured to be trusted by `sshd`. This means OpenSSH nodes will accept certificates that are signed by the User CA. The problem with that is when Teleport users authenticate with a cluster, the Auth server replies with a certificate that is signed by the User CA. Users could potentially use this certificate to directly connect to registered OpenSSH nodes.

Using the new OpenSSH CA to sign certificates used to authenticate with registered OpenSSH nodes solves this problem, as Teleport users do not have access to any certificates signed by the OpenSSH CA.

### UX

The following Teleport node features won't work with registered OpenSSH nodes:

- Enhanced session recording and restricted networking
- Host user provisioning
- Session recording without SSH session termination
- Dynamic labels
- Outbound persistent tunnels to Proxies

### Future work

The OpenSSH CA could be also used to sign certificates for non-registered OpenSSH nodes. If that is done then the same logic could be used to detect non-registered OpenSSH nodes, possibly lifting the 
