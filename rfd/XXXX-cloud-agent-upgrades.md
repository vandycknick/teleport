---
authors: Forrest Marshall (forrest@goteleport.com)
state: draft
---

# RFD XXXX - Cloud Agent Upgrades

## Required Approvers

* Engineering: @klizhentas && (@russjones || @zmb3 || @rosstimothy || @espadolini)

* Cloud: TBD

## What

A simple mechanism for automatically keeping cloud agents on a common "stable"
install channel.

## Why

We would like to increase the cadence at which cloud clusters can be upgraded, and
eliminate the significant overhead incurred by requiring users to manually upgrade agents.

The existing upgrade system proposal is very complex, and many of its features
are only relevant for niche on-prem scenarios. The majority of cloud deployments can be served
by a far simpler system.

This proposal describes a simple framework for keeping cloud agents up to date, designed with the
intent to rely as little as possible on teleport itself for the upgrades.

Because we are targeting a maximally simple system, we will assume that all cloud clusters using this
feature track a single global "stable" channel, and that all agents are installed in one of a short
list of supported contexts.


## Details

From the start, we will support the following scenarios:

- Teleport agents deployed as `k8s` pods using a dedicated `cloud-stable` image.

- Teleport agents installed via a dedicated `cloud-stable` `apt` or `yum` package.

Agents deployed in one of the above manners will automically be "enrolled" in the cloud upgrade system. Enrollment
will not be coordinated at the cluster-level (i.e. agents will not check with the cluster to determine if upgrades
should occur). It will be assumed that the latest available `cloud-stable` package is always the "correct" package
to be running. This is an import divergence from how teleport versioning is typically handled, and has the important
effect of allows unhealthy teleport instances to attempt upgrading as a means of "fixing" themselves.

The only form of "coordination" around agent upgrades will be around restart timing. Since a restart is necessary for
an upgrade to take effect, healthy agents will attempt to schedule their restarts during the next maintenance window of
their current cluster (discussed in more detail later).

Teleport cloud clusters enrolled in the cloud upgrade system will have their control planes frequently upgraded s.t.
their control planes are always compatible with the current version being served on the `cloud-stable` packages/repos.
Control planes will also need to be backwards compatible with any agent version served within at least 3x the maximum
maintenance window interval.

Rollout of a new version to `cloud-stable` will generally follow the following steps:

1. A new target version is selected (but *not* published to the `cloud-stable` repositories).

2. Each cloud control plane is upgraded to the target version during its next maintenance window.

3. The new target version is pushed to the `cloud-stable` repositories (this happens *after* all control
planes have been upgraded, meaning that it occurs a minimum of 1x "max maintenance interval" after the
start of step 2).

4. A grace period of at least 2x "max maintenance interval" is observed, during which agents are expected to upgrade
to the target version. During this grace period the control plane may not be upgraded to a version that might be
incomaptible with any agents that have yet to upgrade.

Note that in practice, wether or not the ordering/timing of the above steps matters depends entirely on what changes
were made between versions. Most minor/patch releases don't actually require this kind of procedure, tho its best to
assume that the procedure is required unless we are rolling out a critical bug fix that was specifically designed to
be self-contained.


### Agent Upgrade Model

In the interest of maximum simplicity, the upgrade model will totally decouple "upgrades" from "restarts". The teleport
agent itself will make no effort to discover wether or not new software is available, and will not attempt to directly
affect an upgrade. Instead, it will rely on three assumptions:

1. If the teleport agent exits, it will be restarted (e.g. by k8s or systemd).

2. When restarted, teleport will be started with the latest version locally available.

3. The locally available version will be updated from remote reasonably frequently. At least
daily during normal operation, and shortly after boot.

Different deployments methods will support this assumption set in different ways. In k8s, we will require use of
`imagePullPolicy: Always`. For `apt`/`yum` installs, we will use a systemd timer to perform scheduled upgrades
(discussed in greater detail below).

With the above assumptions in mind, we can reduce teleport's responsibilities to a small set of conditions under which
teleport must perform a graceful exit:

1. Teleport has not had a healthy connection to auth for some predefined time (2-3 minutes is likely sufficient).

2. Teleport is within a cluster maintenance window and has yet to restart since the window began.

3. Teleport has not restarted for greater than 1.5x "max maintenance interval" (special condition to
mitigate bugs in restart window detection logic).


Healthy teleport agents will use their Instance client to periodically discover the next maintenance window. Agents will
perform their graceful exit at a random time within the maintenance window.

TODO: maintenance window API/protobuf

### Kubernetes Model

For k8s-based deployments the only modifications to our existing deployment model that will be required
will be to target a new `cloud-stable` image or tag, and to use `imagePullPolicy: Always` for all teleport
agent containers. With these changes, teleport cloud agents will automatically be upgraded when their containers
are restarted.

In practice, this will likely mean that we will want to provide custom cloud-specific helm charts (or cloud-specific
flags) that allow users to easily apply the new options to all their agents.  Ex:

```
$ helm install teleport-kube-agent [...]
```

becomes

```
$ helm install teleport-cloud-kube-agent [...]
```

or, alternatively,

```
$ helm install teleport-kube-agent [...] --set kind=cloud
```

Helm is outside of my wheelhouse, so I'll be pulling in some folks with more helm expertise to decide what the
best strategy is here.


### Apt/Yum Model

For `apt` and `yum` based installs, we operate under the assumption that teleport is managed by `systemd`. During
installation we will install a new `teleport-upgrade` systemd timer unit that periodically reinvokes the package
manager to upgrade the teleport installation.

The `teleport-upgrade.timer` unit will invoke a simple `teleport-upgrade` script that runs the appropriate package
manager commands. The timer and script will be the most fragile part of the system. If teleport itself is bugged,
a new healthy teleport can eventually be installed. If a bugged version of the install script is provided, however,
teleport will become orphaned from the `cloud-stable` channel without manual intervention. Because of this
sensitivity, I am leaning toward having the default behavior be to *not* update the timer or script if they already
exist. Nothing prevents us from rolling out a package in the future that *does* overwrite them, but keeping the
old resources by default will ensure that we don't immediately roll out changes to all agents.

---

TODO: More install process details.

---

We will use the `WantedBy` option in the timer, to form a dependency between the teleport service and the upgrade
timer. Because `WantedBy` only takes effect during enable/disable of the unit that presents it, this will ensure that
starting the teleport service starts the upgrade timer by default, but that users can explicitly disable the upgrade
timer with `systemctl` without worrying about it silently being re-enabled.

The timer unit will make use of the `OnBootSec` option to ensure that `teleport-upgrade` is run shortly after bootup,
helping teleport agents "catch up" if their machines have been offline for a while, or if they are starting up from
an older machine image.

We will also use a large `RandomizedDelaySec` to mitigate spikes in repository load.


TODO: write example timer unit.

## Security

TODO


## Future Considerations

TODO
