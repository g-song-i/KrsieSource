// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package core

import (
	"bytes"
	"context"
	"crypto/tls"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	cfg "github.com/g-song-i/KrsieSource/config"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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

// IsK8sEnv Function
func IsK8sEnv() bool {
	// local
	if IsK8sLocal() {
		return true
	}
	return false
}

var err error

func ConfigureHostIP() {

	var hostIP string

	command := "hostname -I | awk '{print $1;}'"
	out, err := exec.Command("bash", "-c", command).Output()
	if err != nil {
		fmt.Sprintf("Failed to execute command: ", command)
	}

	hostIP = strings.TrimSpace(string(out))
	os.Setenv("HOST_IP", hostIP)
	fmt.Println("Successfully set HOST_IP, HOST_IP is: ", hostIP)
}

func ConfigureHostNode() {

	var hostNode string

	command := "kubectl get nodes -o wide | grep $HOST_IP | awk '{print $1;}'"
	out, err := exec.Command("bash", "-c", command).Output()
	if err != nil {
		fmt.Sprintf("Failed to execute command: ", command)
	}

	hostNode = strings.TrimSpace(string(out))
	os.Setenv("HOST_LOCAL_NODE", hostNode)
	fmt.Println("Successfully set HOST_LOCAL_NODE is: ", hostNode)
}

func ConfigureNodePort() {

	var hostPort string

	command := "kubectl cluster-info | grep $HOST_IP | grep proxy | cut -d '/' -f 3 | cut -d ':' -f 2"
	out, err := exec.Command("bash", "-c", command).Output()
	if err != nil {
		fmt.Sprintf("Failed to execute command: ", command)
	}

	hostPort = strings.TrimSpace(string(out))
	os.Setenv("HOST_PORT", hostPort)
	fmt.Println("Successfully set HOST_PORT is: ", hostPort)
}

func ConfigureToken() string {
	var hostToken string
	var hostTokenName string
	var resultToken string

	command := "kubectl get secret -n default | grep default | cut -d ' ' -f 1"
	out, err := exec.Command("bash", "-c", command).Output()
	if err != nil {
		fmt.Sprintf("Failed to execute command: ", command)
	}

	hostTokenName = strings.TrimSpace(string(out))
	// fmt.Println("HOST_TOKEN_NAME is: ", hostTokenName)

	secondCommand := "kubectl get secret " + hostTokenName + " -n default -o yaml | grep token: | cut -d ':' -f 2"
	// fmt.Println(secondCommand)
	secondOut, err := exec.Command("bash", "-c", secondCommand).Output()
	if err != nil {
		fmt.Sprintf("Failed to execute command: ", secondCommand)
	}

	hostToken = strings.TrimSpace(string(secondOut))
	TokenDecode, _ := b64.StdEncoding.DecodeString(hostToken)
	resultToken = string(TokenDecode)

	// fmt.Println("HOST_TOKEN is: ", hostToken)
	fmt.Println("Successfully set host token")
	return resultToken
}

func NewK8sHandler() *K8sHandler {

	kh := &K8sHandler{}

	ConfigureHostIP()
	ConfigureHostNode()
	ConfigureNodePort()
	kh.K8sToken = ConfigureToken()

	if val, ok := os.LookupEnv("HOST_IP"); ok {
		kh.K8sHost = val
		fmt.Printf("Kuberntes Handeler: HOST IP= %s \n", kh.K8sHost)
	} else {
		kh.K8sHost = "127.0.0.1"
		fmt.Printf("Kuberntes Handeler: HOST IP= %s \n", kh.K8sHost)
	}

	if val, ok := os.LookupEnv("HOST_PORT"); ok {
		kh.K8sPort = val
		fmt.Printf("Kuberntes Handeler: HOST PORT= %s \n", kh.K8sPort)
	} else {
		kh.K8sPort = "8001" // kube-proxy
		fmt.Printf("Kuberntes Handeler: HOST PORT= %s \n", kh.K8sPort)
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

	return kh
}

// InitK8sClient Function
func (kh *K8sHandler) InitK8sClient() bool {
	if !IsK8sEnv() { // not Kubernetes
		return false
	}

	if kh.K8sClient == nil {
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

// ============== //
// == API Call == //
// ============== //

// DoRequest Function
func (kh *K8sHandler) DoRequest(cmd string, data interface{}, path string) ([]byte, error) {
	URL := ""
	URL = "http://" + kh.K8sHost + ":" + kh.K8sPort

	pbytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(cmd, URL+path, bytes.NewBuffer(pbytes))
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", kh.K8sToken))

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

	// fmt.Println("%s, pass k8shandler correctly", URL)
	return resp
}

// ========== //
// == Pods == //
// ========== //

// WatchK8sPods Function
func (kh *K8sHandler) WatchK8sPods() *http.Response {
	if !IsK8sEnv() { // not Kubernetes
		return nil
	}

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
				if group.Name == "cnsl.dev.cnsl.krsiepolicy.com" {
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

	// kube-proxy (local)
	URL := "http://" + kh.K8sHost + ":" + kh.K8sPort + "/apis/cnsl.dev.cnsl.krsiepolicy.com/v1alpha1/krsiepolicies?watch=true"

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
