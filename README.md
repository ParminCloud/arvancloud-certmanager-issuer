<p align="center">
  <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" height="256" width="256" alt="cert-manager project logo" />
</p>

# ArvanCloud ACME Webhook for CertManager

[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/arvancloud-webhook)](https://artifacthub.io/packages/search?repo=arvancloud-webhook)
[![Latest release](https://img.shields.io/github/release/ParminCloud/arvancloud-certmanager-issuer.svg)](https://github.com/ParminCloud/arvancloud-certmanager-issuer/releases)

A more simpler and maintainable ACME Webhook Issuer for CertManager Using ArvanCloud DNS/CDN api

## Installation

### Short version

```bash
helm install --repo https://ParminCloud.github.io/arvancloud-certmanager-issuer arvancloud-webhook arvancloud-webhook -n cert-manager
```

### Long version

```bash
helm repo add arvancloud-webhook https://ParminCloud.github.io/arvancloud-certmanager-issuer
helm repo update
helm install --namespace=cert-manager arvancloud-webhook arvancloud-webhook
```

After installation you will get notes about usage based on your provided values

## TODO

* [x] Add documents and usages (For now checkout helm chart NOTES)
* [x] Add CI using GH-Actions and complete Helm chart
* [x] Handle CleanUp
