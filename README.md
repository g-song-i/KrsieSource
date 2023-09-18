# KrsieSource
Kubernetes Runtime Security Instrumentation &amp; Enforcement

![image](https://github.com/g-song-i/blog_image/assets/57793091/f3dd96e2-17bb-494d-9b65-fda390f3d8b6)

This project is inspired by KRSI (Kernel Runtime Security Instrumentation) and KubeArmor to solve runtime security problems in Clou-native environments, which use Kubernetes orchestration system.


* TEST ENVIRONMENT


** 0. REQUIREMENTS ** 

   - Kernel Version 5.7+ (for BPF-LSM)
   - Docker Version 20.10+
   - Kubernets Version 1.20+
   - GoLang 1.19+ 
   - Python 3.8+

** 1. GIVE ROLE TO MASTER NODE ** 

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

** 2. Check KRSIE custom resource exists **

If not, you should deploy KRSIE custom resource with the following command:

```
kubectl apply -f install/KrsiePolicy.yaml
```

**  3. Check default token exists ** 

If you don't have the deafult token in your kubernetes cluster, create it using install/default-token.yaml.

```
kubectl apply -f install/default-token.yaml
```

**  4. Check K8s resources can be accessed ** 

Check RBAC to be sure that you can access K8s resources including pods, nodes and krsie policies. If you can not, create RBAC using install/custom-role.yaml.

```
kubectl apply -f install/custom-role.yaml
```

**  5. Check execution path ** 

Currently, we fix the execution and policies path from $GOPATH. If your code is not inside $GOPATH, it will not work properly.

After setup finishes, you only need to run the command with go command 'go run main.go' simply!