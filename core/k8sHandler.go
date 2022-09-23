// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"

	cfg "github.com/g-song-i/KrsieSource/config"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	rest "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ================= //
// == K8s Handler == //
// ================= //

// K8s Handler
var K8s *K8sHandler

// init Function
func init() {
	K8s = NewK8sHandler()
}

// K8sHandler Structure
type K8sHandler struct {
	K8sClient   *kubernetes.Clientset
	HTTPClient  *http.Client
	WatchClient *http.Client

	K8sToken string
	K8sHost  string
	K8sPort  string
}

// ================ //
// == Kubernetes == //
// ================ //

// IsK8sLocal Function
func IsK8sLocal() bool {
	if !cfg.GlobalCfg.K8sEnv {
		return false
	}

	k8sConfig := os.Getenv("KUBECONFIG")
	if k8sConfig != "" {
		if _, err := os.Stat(filepath.Clean(k8sConfig)); err == nil {
			return true
		}
	}

	home := os.Getenv("HOME")
	if _, err := os.Stat(filepath.Clean(home + "/.kube/config")); err == nil {
		return true
	}

	return false
}

// IsInK8sCluster Function
func IsInK8sCluster() bool {
	if _, ok := os.LookupEnv("KUBERNETES_SERVICE_HOST"); ok {
		return true
	}

	if _, err := os.Stat(filepath.Clean("/run/secrets/kubernetes.io")); err == nil {
		return true
	}

	return false
}

// IsK8sEnv Function
func IsK8sEnv() bool {
	// local
	if IsK8sLocal() {
		return true
	}

	// in-cluster
	if IsInK8sCluster() {
		return true
	}

	return false
}

func NewK8sHandler() *K8sHandler {

	kh := &K8sHandler{}

	// This is just for test. This must be change
	// This will be changed whenever server is rebooted. Need to change
	kh.K8sToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6InM0cVlnNExsZ2I3TWdtbnRpaGYyNTBEa1d6S01BZDNCVnRSNWp1cEx6RncifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tbWdnd3ciLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6ImIzY2E2N2Q5LTExOTgtNDVjZi05NWZlLTMwMTE1MTI5NzQ2NSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.cMTX_BlGoGRt-wjaI6Zh6HeorDO3wJSM7sXp3P8XHuqB1bnWCEIDp3kvHeOp38b6qjDju4uJJd8MOhPbjLYw67deAAVjzJbpzFv1Kci2uvNSbEYsUMi3W-sJnhU5lARIB6PnUTXaQP_SyvbidyDO5G4j5yR7BfZdoshGgUJzt7_kuIucoWOO1qbTpySCVGgGKPeFWn1ZFdleGdaHfvR5nJbIWl-mZvD6fq6Rbj5OcqXR0axBLer4V-wTxssOos86wZqeGf9PW2r32OsMxWnxI7iWtuoJzN3EATzj3CJX_IB0KUAGBGujOLDmjIwO1XO8T0kVKpJ6urXN6pF78CuM9A"

	// speciified an address of a cluster
	kh.K8sHost = "220.70.2.222"
	kh.K8sPort = "6443"

	// create the configuration by token
	kubeConfig := &rest.Config{
		Host:        "https://" + kh.K8sHost + ":" + kh.K8sPort,
		BearerToken: kh.K8sToken,
		// #nosec
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: true,
		},
	}

	kh.HTTPClient = &http.Client{
		Timeout: time.Second * 5,
		// #nosec
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	kh.WatchClient = &http.Client{
		// #nosec
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	client, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil
	}
	kh.K8sClient = client
	// fmt.Println("Here is pass")
	return kh
}

// InitK8sClient Function
func (kh *K8sHandler) InitK8sClient() bool {
	if !IsK8sEnv() { // not Kubernetes
		return false
	}

	if kh.K8sClient == nil {
		if IsInK8sCluster() {
			return kh.InitInclusterAPIClient()
		}
		if IsK8sLocal() {
			return kh.InitLocalAPIClient()
		}
		return false
	}

	return true
}

// InitLocalAPIClient Function
func (kh *K8sHandler) InitLocalAPIClient() bool {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = os.Getenv("HOME") + "/.kube/config"
		if _, err := os.Stat(filepath.Clean(kubeconfig)); err != nil {
			return false
		}
	}

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return false
	}

	// creates the clientset
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return false
	}
	kh.K8sClient = client

	return true
}

// InitInclusterAPIClient Function
func (kh *K8sHandler) InitInclusterAPIClient() bool {
	read, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return false
	}
	kh.K8sToken = string(read)

	// create the configuration by token
	kubeConfig := &rest.Config{
		Host:        "https://" + kh.K8sHost + ":" + kh.K8sPort,
		BearerToken: kh.K8sToken,
		// #nosec
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: true,
		},
	}

	client, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return false
	}
	kh.K8sClient = client

	return true
}

// ============== //
// == API Call == //
// ============== //

// DoRequest Function
func (kh *K8sHandler) DoRequest(cmd string, data interface{}, path string) ([]byte, error) {
	URL := ""

	if IsInK8sCluster() {
		URL = "https://" + kh.K8sHost + ":" + kh.K8sPort
	} else {
		URL = "http://" + kh.K8sHost + ":" + kh.K8sPort
	}

	pbytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(cmd, URL+path, bytes.NewBuffer(pbytes))
	if err != nil {
		return nil, err
	}

	if IsInK8sCluster() {
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", kh.K8sToken))
	}

	resp, err := kh.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if err := resp.Body.Close(); err != nil {
		fmt.Println(err)
	}

	return resBody, nil
}

// ========== //
// == Node == //
// ========== //

// WatchK8sNodes Function
func (kh *K8sHandler) WatchK8sNodes() *http.Response {

	if !IsK8sEnv() { // not Kubernetes
		return nil
	}

	if IsInK8sCluster() { // kube-apiserver
		URL := "https://" + kh.K8sHost + ":" + kh.K8sPort + "/api/v1/nodes?watch=true"

		req, err := http.NewRequest("GET", URL, nil)
		if err != nil {
			return nil
		}

		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", kh.K8sToken))

		resp, err := kh.WatchClient.Do(req)
		if err != nil {
			return nil
		}

		return resp
	}

	URL := "https://" + kh.K8sHost + ":" + kh.K8sPort + "/api/v1/nodes?watch=true"

	// #nosec
	if resp, err := http.Get(URL); err == nil {
		return resp
	}

	return nil
}

// ========== //
// == Pods == //
// ========== //

// WatchK8sPods Function
func (kh *K8sHandler) WatchK8sPods() *http.Response {
	if !IsK8sEnv() { // not Kubernetes
		return nil
	}

	if IsInK8sCluster() { // kube-apiserver
		URL := "https://" + kh.K8sHost + ":" + kh.K8sPort + "/api/v1/pods?watch=true"

		req, err := http.NewRequest("GET", URL, nil)
		if err != nil {
			return nil
		}

		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", kh.K8sToken))

		resp, err := kh.WatchClient.Do(req)
		if err != nil {
			return nil
		}

		return resp
	}

	// kube-proxy (local)
	URL := "http://" + kh.K8sHost + ":" + kh.K8sPort + "/api/v1/pods?watch=true"

	// #nosec
	if resp, err := http.Get(URL); err == nil {
		return resp
	}

	return nil
}

// ====================== //
// == Custom Resources == //
// ====================== //

// CheckCustomResourceDefinition Function
func (kh *K8sHandler) CheckCustomResourceDefinition(resourceName string) bool {

	if !IsK8sEnv() { // not Kubernetes
		return false
	}

	exist := false
	apiGroup := metav1.APIGroup{}

	// check APIGroup
	if resBody, errOut := kh.DoRequest("GET", nil, "/apis"); errOut == nil {
		res := metav1.APIGroupList{}
		if errIn := json.Unmarshal(resBody, &res); errIn == nil {
			for _, group := range res.Groups {
				if group.Name == "security.kubearmor.com" {
					exist = true
					apiGroup = group
					break
				}
			}
		}
	}

	// check APIResource
	if exist {
		if resBody, errOut := kh.DoRequest("GET", nil, "/apis/"+apiGroup.PreferredVersion.GroupVersion); errOut == nil {
			res := metav1.APIResourceList{}
			if errIn := json.Unmarshal(resBody, &res); errIn == nil {
				for _, resource := range res.APIResources {
					if resource.Name == resourceName {
						return true
					}
				}
			}
		}
	}

	return false
}

// WatchK8sSecurityPolicies Function
func (kh *K8sHandler) WatchK8sSecurityPolicies() *http.Response {

	if !IsK8sEnv() { // not Kubernetes
		return nil
	}

	if IsInK8sCluster() {
		URL := "https://" + kh.K8sHost + ":" + kh.K8sPort + "/apis/cnsl.dev.cnsl.krsiepolicy.com/v1alpha1/krsiepolicies?watch=true"

		req, err := http.NewRequest("GET", URL, nil)
		if err != nil {
			return nil
		}

		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", kh.K8sToken))

		resp, err := kh.WatchClient.Do(req)
		if err != nil {
			return nil
		}

		return resp
	}

	// kube-proxy (local)
	URL := "http://" + kh.K8sHost + ":" + kh.K8sPort + "/apis/cnsl.dev.cnsl.krsiepolicy.com/v1alpha1/krsiepolicies?watch=true"

	// #nosec
	if resp, err := http.Get(URL); err == nil {
		return resp
	}

	return nil
}

// ================ //
// == ReplicaSet == //
// ================ //

// GetDeploymentNameControllingReplicaSet Function
func (kh *K8sHandler) GetDeploymentNameControllingReplicaSet(namespaceName, replicaSetName string) string {
	// get replicaSet from k8s api client
	rs, err := kh.K8sClient.AppsV1().ReplicaSets(namespaceName).Get(context.Background(), replicaSetName, metav1.GetOptions{})
	if err != nil {
		return ""
	}

	// check if we have ownerReferences
	if len(rs.ObjectMeta.OwnerReferences) == 0 {
		return ""
	}

	// check if given ownerReferences are for Deployment
	if rs.ObjectMeta.OwnerReferences[0].Kind != "Deployment" {
		return ""
	}

	// return the deployment name
	return rs.ObjectMeta.OwnerReferences[0].Name
}
