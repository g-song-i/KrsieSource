# KrsieSource
Kubernetes Runtime Security Instrumentation &amp; Enforcement

This project is inspired by KRSI (Kernel Runtime Security Instrumentation) and KubeArmor to solve runtime security problems in MEC environments, which use Kubernetes orchestration system.


* TEST ENVIRONMENT

0. REQUIREMENTS
 -> Kernel Version 5.7+
 -> Docker Version 20.10+
 -> GoLang 1.19+
 -> Python 3.8+

1. GIVE ROLE TO MASTER NODE

To test some scenarios successfully, we assume that we can deploy any container to master node. To do this, you need to run the code below

```
kubectl label nodes songi-virtualbox node-role.kubernetes.io/master=
```
