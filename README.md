# KrsieSource
Kubernetes Runtime Security Instrumentation &amp; Enforcement

![image](https://user-images.githubusercontent.com/57793091/202920481-50cadfd0-af58-4fdd-b514-55f090ef11a3.png)

This project is inspired by KRSI (Kernel Runtime Security Instrumentation) and KubeArmor to solve runtime security problems in Cloud-native environments, which use Kubernetes orchestration system.



## TEST ENVIRONMENT


### 0. REQUIREMENTS  

   - Kernel Version 5.7+ (for BPF-LSM)
   - Docker Version 20.10+
   - Kubernets Version 1.20+
   - GoLang 1.19+ 
   - Python 3.8+

### 1. GIVE ROLE TO MASTER NODE  

To test some scenarios successfully, we assume that we can deploy test containers to master node. To do this, you need to run the codes below:

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

###  2. Check default token exists  

As far as we know, after a specific version of K8s, it does not make default token automatically. If you do not have default token, create it using install/default-token.yaml.

###  3. Check if K8s resources can be accessed  

Check RBAC to be sure that you can access K8s resources including pods, nodes and krsie policies. If you can not, create RBAC using install/custom-role.yaml.

###  4. Check execution path  

Currently, we fix the execution and policies path from $GOPATH. If your code is not inside $GOPATH, it will not work properly.
