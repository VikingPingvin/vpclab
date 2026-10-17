# VPCLAB

Practice AWS networking on your own machine, with real traffic and no AWS bill.

Current early state focuses on Windows + WSL flow.

## Motivation

The goal of this project is to simulate AWS-conform networking stack locally, to use as a test-bench, practice and learning.
The tooling enables the definition of VPCs, Security groups and other AWS networking related mechanisms, all simulated through native docker containers.

Long term goals include support for a `Coding Assessment Platform` that can host coding exercises relying on `vpcsim` network/security isolation and multi-tenancy. This is also a great opportunity to learn more about the various layers of isolation and offer the ability to pentest (also a local learning ability)

## Quick start

After the one-time WSL setup (`sudo bash scripts/setup-wsl.sh` inside the
`Ubuntu-24.04` distro), from PowerShell in the repo root:

```powershell
.\vpclab up        # start Floci and vpcsim; keeps WSL running
.\vpclab status    # instances with Name tag, state and IPs
.\vpclab sh web    # shell on the instance with Name tag "web"
.\vpclab dashboard # read-only AWS-console-style UI on http://localhost:4577
.\vpclab down      # stop; .\vpclab up brings everything back
.\vpclab reset     # delete all Floci state and start again
```

Inside WSL, `scripts/vpclab.sh` takes the same commands.

## How it works

There are two pieces:

1. **[Floci](https://floci.io)** emulates the AWS APIs. You create VPCs,
   subnets, security groups and instances against `localhost:4566`, just as
   you would against AWS.
2. **vpcsim** reads that state and builds a real Linux network from it.
   Each EC2 instance becomes a container. Each VPC gets a router namespace
   that applies route tables, security groups and NACLs with nftables.

Every packet passes through the router, even between two instances in the
same subnet. Root inside an instance cannot bypass it, just like on AWS.

Security groups are stateful, NACLs are stateless, and a missing rule gives a real timeout.

Instances behind an internet gateway can reach the real internet. A
simulated "operator laptop" enables testing of inbound access from "outside".