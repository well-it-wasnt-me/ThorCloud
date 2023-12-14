<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://user-images.githubusercontent.com/20483346/222834423-7fc33c17-c599-43c5-827d-ea4183a8b6f2.png" height="80">
    <img alt="logo" src="https://user-images.githubusercontent.com/20483346/222834439-0cbf26d7-eaa6-462c-9438-e3a91a02c7d2.png" height="80">
  </picture>
  <p align="center">
    <em>Secure your cloud.</em>
  </p>
</p>

<div align="center">

---

[![Prs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=shields)](http://makeapullrequest.com)
[![Join Slack](https://img.shields.io/badge/slack%20community-join-blue)](https://join.slack.com/t/ironleapcommunity/shared_invite/zt-1oxm8asmq-4oyM4fdqarSHMoMstGH6Lw)
[![License](https://img.shields.io/badge/license-Apache2.0-brightgreen)](/LICENSE)

---

</div>

<!-- omit in toc -->
## ZeusCloud is an open source cloud security platform. 

Discover, prioritize, and remediate your risks in the cloud. 

- Build an asset inventory of your AWS accounts.
- Discover attack paths based on public exposure, IAM, vulnerabilities, and more.
- Prioritize findings with graphical context. 
- Remediate findings with step by step instructions.
- Customize security and compliance controls to fit your needs. 
- Meet compliance standards PCI DSS, CIS, SOC 2, and more!

<!-- omit in toc -->
## Table of Contents

- [Quick Start](#quick-start)
- [Sandbox](#sandbox)
- [Features](#features)
- [Why ZeusCloud?](#why-zeuscloud)
- [Future Roadmap](#future-roadmap)
- [Contributing](#contributing)
- [Development](#development)
- [Security](#security)
- [Open source vs. paid](#open-source-vs-paid)

## Quick Start

1. Clone repo: `git clone --recurse-submodules git@github.com:Zeus-Labs/ZeusCloud.git`
2. Run: `cd ZeusCloud && make quick-deploy`
3. Visit http://localhost:80

Check out our [Get Started](https://docs.zeuscloud.io/introduction/get-started) guide for 
more details.

A cloud-hosted version is available on special request - email founders@zeuscloud.io to get access!

## Sandbox

Play around with [our sandbox environment](https://demo.zeuscloud.io) to see how ZeusCloud identifies, prioritizes, and remediates risks in the cloud!

## Features

![ZeusCloud](https://user-images.githubusercontent.com/20483346/233917373-fbaf6651-c446-4e3a-b23d-9eb1133e49ac.gif)

* **Discover Attack Paths** - Discover toxic risk combinations an attacker can use to penetrate your environment.
* **Graphical Context** - Understand context behind security findings with graphical visualizations.
* **Access Explorer** - Visualize who has access to what with an IAM visualization engine.
* **Identify Misconfigurations** - Discover the highest risk-of-exploit misconfigurations in your environments.
* **Configurability** - Configure which security rules are active, which alerts should be muted, and more.
* **Security as Code** - Modify rules or write your own with our extensible security as code approach.
* **Remediation** - Follow step by step guides to remediate security findings.
* **Compliance** - Ensure your cloud posture is compliant with PCI DSS, CIS benchmarks and more!


## Why ZeusCloud?
Cloud usage continues to grow. Companies are shifting more of their workloads from on-prem to the cloud and both adding and expanding new and existing workloads in the cloud. Cloud providers keep increasing their offerings and their complexity. Companies are having trouble keeping track of their security risks as their cloud environment scales and grows more complex. Several high profile attacks have occurred in recent times. Capital One had an S3 bucket breached, Amazon had an unprotected Prime Video server breached, Microsoft had an Azure DevOps server breached, Puma was the victim of ransomware, etc.

We had to take action.

- We noticed traditional cloud security tools are opaque, confusing, time consuming to set up, and expensive as you scale your cloud environment
- Cybersecurity vendors don't provide much actionable information to security, engineering, and devops teams by inundating them with non-contextual alerts
- ZeusCloud is easy to set up, transparent, and configurable, so you can prioritize the most important risks 
- Best of all, you can use **ZeusCloud for free**!

## Future Roadmap
- Integrations with vulnerability scanners
- Integrations with secret scanners
- Shift-left: Remediate risks earlier in the SDLC with context from your deployments
- Support for Azure and GCP environments

## Contributing
We love contributions of all sizes. What would be most helpful first: 

- Please give us feedback in our [Slack](https://join.slack.com/t/ironleapcommunity/shared_invite/zt-1oxm8asmq-4oyM4fdqarSHMoMstGH6Lw).
- Open a PR (see our instructions below on developing ZeusCloud locally)
- Submit a feature request or bug report through Github Issues.


## Development

Run containers in development mode:
```
cd frontend && yarn && cd -
docker-compose down && docker-compose -f docker-compose.dev.yaml --env-file .env.dev up --build
```

Reset neo4j and/or postgres data with the following:
```
rm -rf .compose/neo4j
rm -rf .compose/postgres
```

To develop on frontend, make the the code changes and save.

To develop on backend, run
```
docker-compose -f docker-compose.dev.yaml --env-file .env.dev up --no-deps --build backend
```

To access the UI, go to: http://localhost:80.

## Security

Please do not run ZeusCloud exposed to the public internet. Use the latest versions of ZeusCloud to get all security related patches. Report any security vulnerabilities to founders@zeuscloud.io. 

## Open-source vs. cloud-hosted

This repo is freely available under the [Apache 2.0 license](https://github.com/Zeus-Labs/ZeusCloud/blob/main/LICENSE).

We're working on a cloud-hosted solution which handles deployment and infra management. Contact us at founders@zeuscloud.io for more information!

Special thanks to the amazing [Cartography](https://github.com/lyft/cartography) project, which ZeusCloud uses for its asset inventory. Credit to PostHog and Airbyte for inspiration around public-facing materials - like this README!
