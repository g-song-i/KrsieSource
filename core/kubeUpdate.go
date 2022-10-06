// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package core

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	cfg "github.com/g-song-i/KrsieSource/config"
	tp "github.com/g-song-i/KrsieSource/types"
)

// ============ //
// == Common == //
// ============ //

// Clone Function
func Clone(src, dst interface{}) error {
	arr, _ := json.Marshal(src)
	return json.Unmarshal(arr, dst)
}

func matchHost(hostName string) bool {

	envName := os.Getenv("HOST_LOCAL_NODE")
	// fmt.Println("HOST_LOCAL_NODE", envName) // cnsl-mec
	// fmt.Println("cfg.GlobalCfg.Host", cfg.GlobalCfg.Host) // cnsl-MEC
	if envName != "" {
		// fmt.Println("envName is", envName)
		// fmt.Println("hostName is", hostName) // NULL
		return envName == hostName
	}
	nodeName := strings.Split(hostName, ".")[0]
	return nodeName == cfg.GlobalCfg.Host
}

// MatchIdentities Function
func MatchIdentities(identities []string, superIdentities []string) bool {
	matched := true

	// if nothing in identities, skip it
	if len(identities) == 0 {
		return false
	}

	// if super identities not include indentity, return false
	for _, identity := range identities {
		if !ContainsElement(superIdentities, identity) {
			matched = false
			break
		}
	}

	// otherwise, return true
	return matched
}

// WatchK8sNodes Function
func (dm *KrsieDaemon) WatchK8sNodes() {

	fmt.Printf("GlobalCfg.Host=%s, NODENAME=%s \n", cfg.GlobalCfg.Host, os.Getenv("HOST_LOCAL_NODE"))
	for {
		if resp := K8s.WatchK8sNodes(); resp != nil {
			defer resp.Body.Close()

			decoder := json.NewDecoder(resp.Body)
			for {
				event := tp.K8sNodeEvent{}
				if err := decoder.Decode(&event); err == io.EOF {
					break
				} else if err != nil {
					break
				}

				if !matchHost(event.Object.ObjectMeta.Name) {
					continue
				}

				node := tp.Node{}

				// speciified a name of cluster
				node.ClusterName = cfg.GlobalCfg.Cluster
				node.NodeName = cfg.GlobalCfg.Host

				for _, address := range event.Object.Status.Addresses {
					if address.Type == "InternalIP" {
						node.NodeIP = address.Address
						break
					}
				}

				node.Annotations = map[string]string{}
				node.Labels = map[string]string{}
				node.Identities = []string{}

				// update annotations
				for k, v := range event.Object.ObjectMeta.Annotations {
					node.Annotations[k] = v
				}

				// update labels and identities
				for k, v := range event.Object.ObjectMeta.Labels {
					node.Labels[k] = v
					node.Identities = append(node.Identities, k+"="+v)
				}

				sort.Slice(node.Identities, func(i, j int) bool {
					return node.Identities[i] < node.Identities[j]
				})

				// node info
				node.Architecture = event.Object.Status.NodeInfo.Architecture
				node.OperatingSystem = event.Object.Status.NodeInfo.OperatingSystem
				node.OSImage = event.Object.Status.NodeInfo.OSImage
				node.KernelVersion = event.Object.Status.NodeInfo.KernelVersion
				node.KubeletVersion = event.Object.Status.NodeInfo.KubeletVersion

				// container runtime
				node.ContainerRuntimeVersion = event.Object.Status.NodeInfo.ContainerRuntimeVersion

				// fmt.Printf("containerRuntimeversion: %s \n", node.ContainerRuntimeVersion)
				// fmt.Printf("nodeIP: %s \n", node.NodeIP)

				dm.Node = node
			}
		} else {
			time.Sleep(time.Second * 1)
			fmt.Println("response is nil")
		}
	}
}

// GetSHA256ofImage of the image
func GetSHA256ofImage(s string) string {
	if idx := strings.Index(s, "@"); idx != -1 {
		return s[idx:]
	}
	return s
}

// ================ //
// == Pod Update == //
// ================ //

// UpdateEndPointWithPod Function
func (dm *KrsieDaemon) UpdateEndPointWithPod(action string, pod tp.K8sPod) {
	if action == "ADDED" {
		// create a new endpoint
		newPoint := tp.EndPoint{}

		newPoint.NamespaceName = pod.Metadata["namespaceName"]
		newPoint.EndPointName = pod.Metadata["podName"]

		newPoint.Labels = map[string]string{}
		newPoint.Identities = []string{"namespaceName=" + pod.Metadata["namespaceName"]}

		// update labels and identities
		for k, v := range pod.Labels {
			newPoint.Labels[k] = v
			newPoint.Identities = append(newPoint.Identities, k+"="+v)
		}

		sort.Slice(newPoint.Identities, func(i, j int) bool {
			return newPoint.Identities[i] < newPoint.Identities[j]
		})

		newPoint.Containers = []string{}

		// update containers
		for k := range pod.Containers {
			newPoint.Containers = append(newPoint.Containers, k)
		}

		// update containers and apparmors
		dm.ContainersLock.Lock()
		for _, containerID := range newPoint.Containers {
			container := dm.Containers[containerID]

			container.NamespaceName = newPoint.NamespaceName
			container.EndPointName = newPoint.EndPointName

			labels := []string{}
			for k, v := range newPoint.Labels {
				labels = append(labels, k+"="+v)
			}
			container.Labels = strings.Join(labels, ",")

			container.ContainerName = pod.Containers[containerID]
			container.ContainerImage = pod.ContainerImages[containerID]

			dm.Containers[containerID] = container
		}
		dm.ContainersLock.Unlock()

		newPoint.SecurityPolicies = dm.GetSecurityPolicies(newPoint.Identities)
		dm.EndPointsLock.Lock()

		// add the endpoint into the endpoint list
		dm.EndPoints = append(dm.EndPoints, newPoint)
		dm.EndPointsLock.Unlock()

	} else if action == "MODIFIED" {
		newEndPoint := tp.EndPoint{}

		dm.EndPointsLock.Lock()
		for _, endPoint := range dm.EndPoints {
			if pod.Metadata["namespaceName"] == endPoint.NamespaceName && pod.Metadata["podName"] == endPoint.EndPointName {
				newEndPoint = endPoint
			}
		}
		dm.EndPointsLock.Unlock()

		newEndPoint.Labels = map[string]string{}
		newEndPoint.Identities = []string{"namespaceName=" + pod.Metadata["namespaceName"]}

		// update labels and identities
		for k, v := range pod.Labels {
			newEndPoint.Labels[k] = v
			newEndPoint.Identities = append(newEndPoint.Identities, k+"="+v)
		}

		sort.Slice(newEndPoint.Identities, func(i, j int) bool {
			return newEndPoint.Identities[i] < newEndPoint.Identities[j]
		})

		newEndPoint.Containers = []string{}

		// update containers
		for k := range pod.Containers {
			newEndPoint.Containers = append(newEndPoint.Containers, k)
		}

		// update containers
		dm.ContainersLock.Lock()
		for _, containerID := range newEndPoint.Containers {
			container := dm.Containers[containerID]

			container.NamespaceName = newEndPoint.NamespaceName
			container.EndPointName = newEndPoint.EndPointName

			labels := []string{}
			for k, v := range newEndPoint.Labels {
				labels = append(labels, k+"="+v)
			}
			container.Labels = strings.Join(labels, ",")

			container.ContainerName = pod.Containers[containerID]
			container.ContainerImage = pod.ContainerImages[containerID]
			dm.Containers[containerID] = container
		}
		dm.ContainersLock.Unlock()

		// get security policies according to the updated identities
		newEndPoint.SecurityPolicies = dm.GetSecurityPolicies(newEndPoint.Identities)

		dm.EndPointsLock.Lock()

		for idx, endPoint := range dm.EndPoints {
			if pod.Metadata["namespaceName"] == endPoint.NamespaceName && pod.Metadata["podName"] == endPoint.EndPointName {
				dm.EndPoints[idx] = newEndPoint
			}
		}

		dm.EndPointsLock.Unlock()

	} else { // DELETED
		dm.EndPointsLock.Lock()
		for idx, endPoint := range dm.EndPoints {
			if pod.Metadata["namespaceName"] == endPoint.NamespaceName && pod.Metadata["podName"] == endPoint.EndPointName {
				// remove endpoint
				dm.EndPoints = append(dm.EndPoints[:idx], dm.EndPoints[idx+1:]...)
				break
			}
		}
		dm.EndPointsLock.Unlock()
	}
}

// WatchK8sPods Function
func (dm *KrsieDaemon) WatchK8sPods() {
	for {
		if resp := K8s.WatchK8sPods(); resp != nil {
			defer resp.Body.Close()

			decoder := json.NewDecoder(resp.Body)
			for {
				event := tp.K8sPodEvent{}
				if err := decoder.Decode(&event); err == io.EOF {
					break
				} else if err != nil {
					break
				}

				if event.Type != "ADDED" && event.Type != "MODIFIED" && event.Type != "DELETED" {
					continue
				}

				// create a pod

				pod := tp.K8sPod{}

				pod.Metadata = map[string]string{}
				pod.Metadata["namespaceName"] = event.Object.ObjectMeta.Namespace
				pod.Metadata["podName"] = event.Object.ObjectMeta.Name

				if len(event.Object.ObjectMeta.OwnerReferences) > 0 {
					if event.Object.ObjectMeta.OwnerReferences[0].Kind == "ReplicaSet" {
						deploymentName := K8s.GetDeploymentNameControllingReplicaSet(pod.Metadata["namespaceName"], event.Object.ObjectMeta.OwnerReferences[0].Name)
						if deploymentName != "" {
							pod.Metadata["deploymentName"] = deploymentName
						}
					}
				}

				pod.Annotations = map[string]string{}
				for k, v := range event.Object.Annotations {
					pod.Annotations[k] = v
				}

				pod.Labels = map[string]string{}
				for k, v := range event.Object.Labels {
					if k == "pod-template-hash" {
						continue
					}

					if k == "pod-template-generation" {
						continue
					}

					if k == "controller-revision-hash" {
						continue
					}
					pod.Labels[k] = v
				}

				pod.Containers = map[string]string{}
				pod.ContainerImages = map[string]string{}
				for _, container := range event.Object.Status.ContainerStatuses {
					if len(container.ContainerID) > 0 {
						if strings.HasPrefix(container.ContainerID, "docker://") {
							containerID := strings.TrimPrefix(container.ContainerID, "docker://")
							pod.Containers[containerID] = container.Name
							pod.ContainerImages[containerID] = container.Image + GetSHA256ofImage(container.ImageID)
						} else if strings.HasPrefix(container.ContainerID, "containerd://") {
							containerID := strings.TrimPrefix(container.ContainerID, "containerd://")
							pod.Containers[containerID] = container.Name
							pod.ContainerImages[containerID] = container.Image + GetSHA256ofImage(container.ImageID)
						}
					}
				}
				// update a endpoint corresponding to the pod
				dm.UpdateEndPointWithPod(event.Type, pod)
			}
		} else {
			time.Sleep(time.Second * 1)
		}
	}
}

// WatchSecurityPolicies Function
func (dm *KrsieDaemon) WatchK8sSecurityPolicies() {
	for {
		if !K8s.CheckCustomResourceDefinition("krsiepolicies") {
			time.Sleep(time.Second * 1)
			continue
		}

		if resp := K8s.WatchK8sSecurityPolicies(); resp != nil {
			defer resp.Body.Close()

			decoder := json.NewDecoder(resp.Body)
			for {
				event := tp.K8sBpfPolicyEvent{}
				if err := decoder.Decode(&event); err == io.EOF {
					break
				} else if err != nil {
					break
				}

				if event.Object.Status.Status != "" && event.Object.Status.Status != "OK" {
					continue
				}

				if event.Type != "ADDED" && event.Type != "MODIFIED" && event.Type != "DELETED" {
					continue
				}

				// create a security policy

				secPolicy := tp.SecurityPolicy{}

				secPolicy.Metadata = map[string]string{}
				secPolicy.Metadata["namespaceName"] = event.Object.Metadata.Namespace
				secPolicy.Metadata["policyName"] = event.Object.Metadata.Name

				fmt.Printf("secpolicy_namespace %s \n", secPolicy.Metadata["namespaceName"])
				fmt.Printf("policy_name %s \n", secPolicy.Metadata["policyName"])

				if err := Clone(event.Object.Spec, &secPolicy.Spec); err != nil {
					fmt.Printf("Failed to clone a spec (%s)", err.Error())
					continue
				}

				// add identities

				secPolicy.Spec.Selector.Identities = []string{"namespaceName=" + event.Object.Metadata.Namespace}

				for k, v := range secPolicy.Spec.Selector.MatchLabels {
					secPolicy.Spec.Selector.Identities = append(secPolicy.Spec.Selector.Identities, k+"="+v)
				}

				sort.Slice(secPolicy.Spec.Selector.Identities, func(i, j int) bool {
					return secPolicy.Spec.Selector.Identities[i] < secPolicy.Spec.Selector.Identities[j]
				})

				/*
					fmt.Printf("security spec, name: %s \n", secPolicy.Spec.Name)
					fmt.Printf("security spec, lsm name: %s \n", secPolicy.Spec.LsmName)
					fmt.Printf("security spec, condition parameter: %s \n", event.Object.Spec.Conditions[0].Parameter)
					fmt.Printf("security spec, condition operator: %s \n", event.Object.Spec.Conditions[0].Operator)
					fmt.Printf("security spec, condition value: %s \n", event.Object.Spec.Conditions[0].Value)
					fmt.Printf("security spec, condition action: %s \n", event.Object.Spec.Conditions[0].Action)
					fmt.Println("========= security policy information =========")
					fmt.Println("")
				*/

				// update a security policy into the policy list

				dm.SecurityPoliciesLock.Lock()

				if event.Type == "ADDED" {
					new := true
					for _, policy := range dm.SecurityPolicies {
						if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
							new = false
							break
						}
					}
					if new {
						dm.SecurityPolicies = append(dm.SecurityPolicies, secPolicy)
					}
				} else if event.Type == "MODIFIED" {
					for idx, policy := range dm.SecurityPolicies {
						if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
							dm.SecurityPolicies[idx] = secPolicy
							break
						}
					}
				} else if event.Type == "DELETED" {
					for idx, policy := range dm.SecurityPolicies {
						if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
							dm.SecurityPolicies = append(dm.SecurityPolicies[:idx], dm.SecurityPolicies[idx+1:]...)
							break
						}
					}
				}

				dm.SecurityPoliciesLock.Unlock()

				// apply security policies to pods
				dm.UpdateSecurityPolicy(event.Type, secPolicy)
			}
		}
	}
}

// update security policy

// UpdateSecurityPolicy Function
func (dm *KrsieDaemon) UpdateSecurityPolicy(action string, secPolicy tp.SecurityPolicy) {
	dm.EndPointsLock.Lock()
	defer dm.EndPointsLock.Unlock()

	for idx, endPoint := range dm.EndPoints {
		// update a security policy
		if MatchIdentities(secPolicy.Spec.Selector.Identities, endPoint.Identities) {
			if action == "ADDED" {
				// add a new security policy if it doesn't exist
				new := true
				for _, policy := range endPoint.SecurityPolicies {
					if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
						new = false
						break
					}
				}
				if new {
					dm.EndPoints[idx].SecurityPolicies = append(dm.EndPoints[idx].SecurityPolicies, secPolicy)
				}
			} else if action == "MODIFIED" {
				for idxP, policy := range endPoint.SecurityPolicies {
					if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
						dm.EndPoints[idx].SecurityPolicies[idxP] = secPolicy
						break
					}
				}
			} else if action == "DELETED" {
				// remove the given policy from the security policy list of this endpoint
				for idxP, policy := range endPoint.SecurityPolicies {
					if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
						dm.EndPoints[idx].SecurityPolicies = append(dm.EndPoints[idx].SecurityPolicies[:idxP], dm.EndPoints[idx].SecurityPolicies[idxP+1:]...)
						break
					}
				}
			}
		}
	}
}

// ============================ //
// == Security Policy Update == //
// ============================ //

// GetSecurityPolicies Function
func (dm *KrsieDaemon) GetSecurityPolicies(identities []string) []tp.SecurityPolicy {
	dm.SecurityPoliciesLock.Lock()
	defer dm.SecurityPoliciesLock.Unlock()

	secPolicies := []tp.SecurityPolicy{}

	for _, policy := range dm.SecurityPolicies {
		if MatchIdentities(policy.Spec.Selector.Identities, identities) {
			secPolicy := tp.SecurityPolicy{}
			if err := Clone(policy, &secPolicy); err != nil {
				fmt.Printf("Failed to clone a policy (%s)", err.Error())
			}
			secPolicies = append(secPolicies, secPolicy)
		}
	}

	return secPolicies
}
