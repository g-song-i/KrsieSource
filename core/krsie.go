// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor
// Modified by: Songi Gwak, Sept 2022

package core

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	cfg "github.com/g-song-i/KrsieSource/config"
	tp "github.com/g-song-i/KrsieSource/types"
)

// ====================== //
// == KrsieDaemon Daemon == //
// ====================== //

// StopChan Channel
var StopChan chan struct{}

// init Function
func init() {
	StopChan = make(chan struct{})
}

// KrsieDaemon Structure
type KrsieDaemon struct {
	// node
	Node tp.Node

	// flag
	K8sEnabled bool

	// K8s pods (from kubernetes)
	K8sPods     []tp.K8sPod
	K8sPodsLock *sync.RWMutex

	// containers (from docker)
	Containers     map[string]tp.Container
	ContainersLock *sync.RWMutex

	// endpoints
	EndPoints     []tp.EndPoint
	EndPointsLock *sync.RWMutex

	// Security policies
	SecurityPolicies     []tp.SecurityPolicy
	SecurityPoliciesLock *sync.RWMutex

	// not used
	// pid map
	ActiveHostPidMap map[string]tp.PidMap
	ActivePidMapLock *sync.RWMutex

	// WgDaemon Handler
	WgDaemon sync.WaitGroup
}

// NewKrsieDaemon Function
func NewKrsieDaemon() *KrsieDaemon {
	dm := new(KrsieDaemon)

	dm.Node = tp.Node{}

	dm.K8sEnabled = false

	dm.K8sPods = []tp.K8sPod{}
	dm.K8sPodsLock = new(sync.RWMutex)

	dm.Containers = map[string]tp.Container{}
	dm.ContainersLock = new(sync.RWMutex)

	dm.EndPoints = []tp.EndPoint{}
	dm.EndPointsLock = new(sync.RWMutex)

	dm.SecurityPolicies = []tp.SecurityPolicy{}
	dm.SecurityPoliciesLock = new(sync.RWMutex)

	// not used
	dm.ActiveHostPidMap = map[string]tp.PidMap{}
	dm.ActivePidMapLock = new(sync.RWMutex)

	dm.WgDaemon = sync.WaitGroup{}

	return dm
}

// DestroyKubeArmorDaemon Function
func (dm *KrsieDaemon) DestroyKrsieDaemon() {

	// wait for other routines
	fmt.Println("Waiting for routine terminations")
	dm.WgDaemon.Wait()

}

// ==================== //
// == Signal Handler == //
// ==================== //

// GetOSSigChannel Function
func GetOSSigChannel() chan os.Signal {
	c := make(chan os.Signal, 1)

	signal.Notify(c,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		os.Interrupt)

	return c
}

// ========== //
// == Main == //
// ========== //

func Krsie() {

	// create a daemon
	dm := NewKrsieDaemon()

	if cfg.GlobalCfg.K8sEnv {
		if !K8s.InitK8sClient() {
			fmt.Println("Failed to initialize Kubernetes client")
			// destroy the daemon
			dm.DestroyKrsieDaemon()

			return
		}
	}

	fmt.Println("Initialized Kubernetes client")

	// get kubernetes node information
	go dm.WatchK8sNodes()
	fmt.Println("Started to monitor node events")

	// wait for a while
	time.Sleep(time.Second * 1)

	for timeout := 0; timeout <= 60; timeout++ {
		if dm.Node.NodeIP != "" {
			break
		}
		if dm.Node.NodeIP == "" && timeout == 60 {
			fmt.Println("node information is not available, terminating")
			break
		}
		fmt.Println("node information is not available")
		// wait for a while
		time.Sleep(time.Second * 1)
	}

	// can get node information properly
	fmt.Printf("Node Name: %s \n", dm.Node.NodeName)
	fmt.Printf("Node IP: %s \n", dm.Node.NodeIP)
	fmt.Printf("Node Annotations: %v \n", dm.Node.Annotations)
	fmt.Printf("OS Image: %s \n", dm.Node.OSImage)
	fmt.Printf("Kernel Version: %s \n", dm.Node.KernelVersion)
	fmt.Printf("Kubelet Version: %s \n", dm.Node.KubeletVersion)
	fmt.Printf("Container Runtime: %s \n", dm.Node.ContainerRuntimeVersion)
	fmt.Println("=====End of Node Information=====")
	fmt.Println("")

	// get and watch pods which a container rumtime is docker
	// need to implement watch function for containerd event
	// need to handle PID mapping for enforcemenet
	// can get pods information properly
	if strings.HasPrefix(dm.Node.ContainerRuntimeVersion, "docker") {
		sockFile := false

		for _, candidate := range []string{"/var/run/docker.sock"} {
			if _, err := os.Stat(candidate); err == nil {
				sockFile = true
				break
			}
		}

		if sockFile {
			// update already deployed containers
			dm.GetAlreadyDeployedDockerContainers()

			// monitor docker events
			go dm.MonitorDockerEvents()
		}
	}

	// == //

	// wait for a while
	time.Sleep(time.Second * 1)

	// == //

	// watch k8s pods
	go dm.WatchK8sPods()
	fmt.Println("Started to monitor Pod events")

	// watch security policies
	go dm.WatchK8sSecurityPolicies()
	fmt.Println("Started to monitor security policies")

	// wait for a while
	time.Sleep(time.Second * 2)

	// == //

	// enforcer
	go dm.Bpfenforcer()
	fmt.Println("Started to enforce policies")

	// listen for interrupt signals
	sigChan := GetOSSigChannel()
	<-sigChan
	fmt.Println("Got a signal to terminate BpfEnforcer")
	close(StopChan)

}
