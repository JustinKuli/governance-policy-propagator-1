[comment]: # ( Copyright Contributors to the Open Cluster Management project )

# Governance Policy Propagator [![KinD tests](https://github.com/open-cluster-management-io/governance-policy-propagator/actions/workflows/kind.yml/badge.svg?branch=main&event=push)](https://github.com/open-cluster-management-io/governance-policy-propagator/actions/workflows/kind.yml)[![License](https://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

## Description

The governance policy propagator is a controller that watches `Policies`, `PlacementBindings`, and `PlacementRules`. It manages replicated Policies in cluster namespaces based on the PlacementBindings and PlacementRules, and it updates the status on Policies to show aggregated cluster compliance results. This controller is a part of the [governance-policy-framework](https://github.com/open-cluster-management/governance-policy-framework).

The operator watches for changes to trigger a reconcile:

1. Changes to Policies in non-cluster namespaces trigger a self reconcile.
2. Changes to Policies in cluster namespaces trigger a root Policy reconcile.
2. Changes to PlacementBindings trigger reconciles on the subject Policies. 
3. Changes to PlacementRules trigger reconciles on subject Policies.

Every reconcile does the following:

1. Creates/updates/deletes replicated policies in cluster namespaces based on PlacementBinding/PlacementRule results.
2. Creates/updates/deletes the policy status to show aggregated cluster compliance results.


Go to the [Contributing guide](CONTRIBUTING.md) to learn how to get involved.

## Geting started 

Check the [Security guide](SECURITY.md) if you need to report a security issue.

### Build and deploy locally
You will need [kind](https://kind.sigs.k8s.io/docs/user/quick-start/) installed.

```bash
make kind-bootstrap-cluster-dev
make build-images
make kind-deploy-controller-dev
```
### Running tests
```
make test-dependencies
make test

make e2e-dependencies
make e2e-test
```

### Clean up
```
make kind-delete-cluster
```

### Updating Deployment resources
Some of the deployment resources are generated by kubebuilder - the crds are generated into `./deploy/crds` and the rbac details from kubebuilder comments are compiled into `./deploy/rbac/role.yaml`.  Other details are managed independently - in particular, the details in `./deploy/manager/manager.yaml`. When any of those details need to be changed, the main deployment yaml `./deploy/operator.yaml` must be regenerated through the `make generate-operator-yaml` target. The `./deploy/operator.yaml` SHOULD NOT be manually updated.

## References

- The `governance-policy-propagator` is part of the `open-cluster-management` community. For more information, visit: [open-cluster-management.io](https://open-cluster-management.io).

<!---
Date: 8/18/2021
-->
