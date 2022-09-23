// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package types

import (
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ============ //
// == Docker == //
// ============ //

// Container Structure
type Container struct {
	ContainerID    string `json:"containerID"`
	ContainerName  string `json:"containerName"`
	ContainerImage string `json:"containerImage"`

	NamespaceName string `json:"namespaceName"`
	EndPointName  string `json:"endPointName"`
	Labels        string `json:"labels"`

	// == //

	PidNS uint32 `json:"pidns"`
	MntNS uint32 `json:"mntns"`

	MergedDir string `json:"mergedDir"`
}

// EndPoint Structure
type EndPoint struct {
	NamespaceName string `json:"namespaceName"`
	EndPointName  string `json:"endPointName"`

	Labels     map[string]string `json:"labels"`
	Identities []string          `json:"identities"`

	Containers []string `json:"containers"`

	SecurityPolicies []SecurityPolicy `json:"securityPolicies"`
}

// Node Structure
type Node struct {
	ClusterName string `json:"clusterName"`
	NodeName    string `json:"nodeName"`
	NodeIP      string `json:"nodeIP"`

	Annotations map[string]string `json:"annotations"`
	Labels      map[string]string `json:"labels"`

	Identities []string `json:"identities"`

	Architecture    string `json:"architecture"`
	OperatingSystem string `json:"operatingSystem"`
	OSImage         string `json:"osImage"`
	KernelVersion   string `json:"kernelVersion"`
	KubeletVersion  string `json:"kubeletVersion"`

	ContainerRuntimeVersion string `json:"containerRuntimeVersion"`
}

// ================ //
// == Kubernetes == //
// ================ //

// K8sNodeEvent Structure
type K8sNodeEvent struct {
	Type   string  `json:"type"`
	Object v1.Node `json:"object"`
}

// K8sPod Structure
type K8sPod struct {
	Metadata        map[string]string
	Annotations     map[string]string
	Labels          map[string]string
	Containers      map[string]string
	ContainerImages map[string]string
}

// K8sPodEvent Structure
type K8sPodEvent struct {
	Type   string `json:"type"`
	Object v1.Pod `json:"object"`
}

// K8sPolicyStatus Structure
type K8sPolicyStatus struct {
	Status string `json:"status,omitempty"`
}

// K8sBpfPolicyEvent Structure
type K8sBpfPolicyEvent struct {
	Type   string       `json:"type"`
	Object K8sBpfPolicy `json:"object"`
}

// K8sBpfPolicy Structure
type K8sBpfPolicy struct {
	Metadata metav1.ObjectMeta `json:"metadata"`
	Spec     SecuritySpec      `json:"spec"`
	Status   K8sPolicyStatus   `json:"status,omitempty"`
}

// K8sBpfPolicyList Structure
type K8sPolicyList struct {
	Items []K8sPolicyList `json:"items"`
}

// ===================== //
// == Security Policy == //
// ===================== //

// SelectorType Structure
type SelectorType struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
	Identities  []string          `json:"identities,omitempty"` // set during policy update
}

// SecuritySpec Structure
type SecuritySpec struct {
	Selector SelectorType `json:"selector"`

	Name    string `json:"syscall,omitempty"`
	LsmName string `json:"lsmHook,omitempty"`

	Conditions []MatchConditionsType `json:"conditions,omitempty"`

	// To distinguish among pods
	Tags    []string `json:"tags,omitempty"`
	Message string   `json:"message,omitempty"`
}

// SecurityPolicy Structure
type SecurityPolicy struct {
	Metadata map[string]string `json:"metadata"`
	Spec     SecuritySpec      `json:"spec"`
}

type MatchConditionsType struct {
	Parameter string `json:"parameter,omitempty"`
	Operator  string `json:"operator,omitempty"`
	Value     string `json:"value,omitempty"`

	Action string `json:"action"`
}

// ================== //
// == Process Tree == //
// ================== //

// PidMap for host pid -> process node
type PidMap map[uint32]PidNode

// PidNode Structure
type PidNode struct {
	PidID uint32
	MntID uint32

	HostPPID uint32
	HostPID  uint32

	PPID uint32
	PID  uint32
	UID  uint32

	ParentExecPath string
	ExecPath       string

	Source string
	Args   string

	Exited     bool
	ExitedTime time.Time
}
