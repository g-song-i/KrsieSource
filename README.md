# KrsieSource
Kubernetes Runtime Security Instrumentation &amp; Enforcement

This project is inspired by KRSI (Kernel Runtime Security Instrumentation) and KubeArmor to solve runtime security problems in MEC environments, which use Kubernetes orchestration system.


* TEST ENVIRONMENT

0. REQUIREMENTS

   - Kernel Version 5.7+
   - Docker Version 20.10+
   - GoLang 1.19+
   - Python 3.8+

1. GIVE ROLE TO MASTER NODE

To test some scenarios successfully, we assume that we can deploy test containers to master node. To do this, you need to run the code below:

Check your control-plane node if it is tainted using a command below:
```
kubectl describe node $NODE_NAME | grep Taints
```

To make a node untained by a role (role name would be different depending on the role name we checked from above):
```
kubectl taint nodes $NODE_NAME node-role.kubernetes.io/master-
```

If your control-plane does not have the role, then label it using command below:
```
kubectl label nodes $NODE_NAME node-role.kubernetes.io/master=
```
