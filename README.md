# InterLink HTCondor Sidecar Plugin

[![InterLink Compatible](https://img.shields.io/badge/InterLink-v0.5.0+-blue)](https://github.com/interlink-hq/interLink)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)

This repository contains an InterLink HTCondor sidecar plugin - a container manager that interfaces with [InterLink](https://github.com/interlink-hq/interLink) instances to deploy Kubernetes pod containers on HTCondor batch systems using Singularity/Apptainer.

## Features

- **Full Kubernetes Pod Support**: Handles containers, volumes, secrets, configMaps, and resource requests
- **Dual Execution Modes**: Singularity containers and host-based script execution  
- **InterLink API v0.5.0+ Compatible**: Modern API with proper error handling and status codes
- **Comprehensive Logging**: Aggregated stdout, stderr, and HTCondor job logs
- **Real-time Status**: Live job status with actual timestamps from HTCondor
- **Robust Error Handling**: Detailed error responses and validation

## Quick Start

### Prerequisites

- Python 3.6+
- HTCondor installation with command-line tools
- Access to HTCondor scheduler and collector
- Grid proxy certificate (for GSI authentication)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/interlink-hq/interlink-htcondor-plugin.git
   cd interlink-htcondor-plugin
   ```

2. **Install dependencies:**
   ```bash
   pip install flask pyyaml
   ```

3. **Configure the plugin:**
   Edit [SidecarConfig.yaml](SidecarConfig.yaml) to set:
   - `DataRootFolder`: Directory for job files (default: `.knoc/`)
   - `CommandPrefix`: Optional command prefix for job execution
   - `ExportPodData`: Enable volume and secret mounting

4. **Create required directories:**
   ```bash
   mkdir -p .knoc out err log
   ```

### Running the Server

```bash
python3 handles.py \
  --condor-config /path/to/condor_config \
  --schedd-host scheduler.example.com \
  --collector-host collector.example.com \
  --auth-method GSI \
  --proxy /tmp/x509up_u$(id -u) \
  --port 8000
```

The server will start on `http://0.0.0.0:8000/` with REST API endpoints:
- `POST /create` - Submit new pods as HTCondor jobs
- `POST /delete` - Cancel and remove jobs
- `GET /status` - Query job status and container states  
- `GET /getLogs` - Retrieve job output and logs

### Authentication

For GSI authentication, ensure certificates are in `/etc/grid-security/certificates` and a valid proxy exists at the specified `--proxy` path.

If Virtual Kubelet and Interlink instances are running and properly configured, you can then test deploying:

```bash
kubectl apply -f ./tests/test_configmap.yaml
kubectl apply -f ./tests/test_secret.yaml
kubectl apply -f ./tests/busyecho_k8s.yaml
```

A special behaviour is triggered if the image is in the form `host`.
The plugin will submit the script which is passed as argument:

```bash
kubectl apply -f ./tests/production_deployment_LNL.yaml
```

# Template for interTwin repositories

This repository is to be used as a repository template for creating a new interTwin
repository, and is aiming at being a clean basis promoting currently accepted
good practices.

It includes:

- License information
- Copyright and author information
- Code of conduct and contribution guidelines
- Templates for PR and issues
- Code owners file for automatic assignment of PR reviewers
- [GitHub actions](https://github.com/features/actions) workflows for linting
  and checking links

Content is based on:

- [Contributor Covenant](http://contributor-covenant.org)
- [Semantic Versioning](https://semver.org/)
- [Chef Cookbook Contributing Guide](https://github.com/chef-cookbooks/community_cookbook_documentation/blob/master/CONTRIBUTING.MD)

## GitHub repository management rules

All changes should go through Pull Requests.

### Merge management

- Only squash should be enforced in the repository settings.
- Update commit message for the squashed commits as needed.

### Protection on main branch

To be configured on the repository settings.

- Require pull request reviews before merging
  - Dismiss stale pull request approvals when new commits are pushed
  - Require review from Code Owners
- Require status checks to pass before merging
  - GitHub actions if available
  - Other checks as available and relevant
  - Require branches to be up to date before merging
- Include administrators
