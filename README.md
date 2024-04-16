# InterLink HTCondor sidecar

This repo contains the code of an InterLink HTCondor sidecar, i.e. a container manager plugin which interacts with
 an [InterLink](https://github.com/interTwin-eu/interLink/tree/main) instance and allows the deployment of pod's
 singularity containers on a local or remote HTCondor batch system.

## Quick start

First of all, let's download this repo:

```bash
git clone https://github.com/ttedeschi/InterLink_HTCondor_sidecar.git
```

modify the [config file](SidecarConfig.yaml) properly.
Then to run the server you just have to enter:

```bash
cd InterLink_HTCondor_sidecar
python3 handles.py --condor-config <path_to_condor_config_file> --schedd-host <schedd_host_url> --collector-host <collector_host_url> --auth-method <authentication_method> --debug <debug_option> --proxy <path_to_proxyfile> --port <server_port>
```

It will be served by default at `http://0.0.0.0:8000/`. In case of GSI authentication, certificates should be placed in `/etc/grid-security/certificates`.

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
