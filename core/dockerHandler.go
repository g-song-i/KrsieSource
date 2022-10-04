// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/client"

	tp "github.com/g-song-i/KrsieSource/types"
)

// ==================== //
// == Docker Handler == //
// ==================== //

// Docker Handler
var Docker *DockerHandler

// init Function
func init() {
	Docker = NewDockerHandler()
}

// DockerVersion Structure
type DockerVersion struct {
	APIVersion string `json:"ApiVersion"`
}

// DockerHandler Structure
type DockerHandler struct {
	DockerClient *client.Client
	Version      DockerVersion
}

// ContainsElement Function
func ContainsElement(slice interface{}, element interface{}) bool {
	switch reflect.TypeOf(slice).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(slice)

		for i := 0; i < s.Len(); i++ {
			val := s.Index(i).Interface()
			if reflect.DeepEqual(val, element) {
				return true
			}
		}
	}
	return false
}

func GetCommandOutputWithErr(cmd string, args []string) (string, error) {
	// #nosec
	res := exec.Command(cmd, args...)
	stdin, err := res.StdinPipe()
	if err != nil {
		return "", err
	}

	go func() {
		defer stdin.Close()
		_, _ = io.WriteString(stdin, "values written to stdin are passed to cmd's standard input")
	}()

	out, err := res.CombinedOutput()
	if err != nil {
		return string(out), err
	}

	return string(out), nil
}

// NewDockerHandler Function
func NewDockerHandler() *DockerHandler {
	docker := &DockerHandler{}

	// specify the docker api version that we want to use
	// Versioned API: https://docs.docker.com/engine/api/

	versionStr, err := GetCommandOutputWithErr("curl", []string{"--silent", "--unix-socket", "/var/run/docker.sock", "http://localhost/version"})
	if err != nil {
		fmt.Println("error occur when get a docker version")
		return nil
	}

	if err := json.Unmarshal([]byte(versionStr), &docker.Version); err != nil {
		fmt.Printf("Unable to get Docker version (%s)", err.Error())
	}

	apiVersion, _ := strconv.ParseFloat(docker.Version.APIVersion, 64)

	if apiVersion >= 1.39 {
		// downgrade the api version to 1.39
		if err := os.Setenv("DOCKER_API_VERSION", "1.39"); err != nil {
			fmt.Printf("Unable to set DOCKER_API_VERSION (%s) \n", err.Error())
		}
	} else {
		// set the current api version
		if err := os.Setenv("DOCKER_API_VERSION", docker.Version.APIVersion); err != nil {
			fmt.Printf("Unable to set DOCKER_API_VERSION (%s) \n", err.Error())
		}
	}

	// create a new client with the above env variable
	DockerClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		fmt.Println("error occur when initialize docker client")
		return nil
	}
	docker.DockerClient = DockerClient

	fmt.Printf("Initialized Docker Handler (version: %s) \n", docker.Version.APIVersion)
	fmt.Println("===========Init Docker Handler============")
	fmt.Println("")

	return docker
}

// Close Function
func (dh *DockerHandler) Close() {
	if dh.DockerClient != nil {
		if err := dh.DockerClient.Close(); err != nil {
			fmt.Printf(err.Error())
		}
	}
}

// ==================== //
// == Container Info == //
// ==================== //

// GetContainerInfo Function
func (dh *DockerHandler) GetContainerInfo(containerID string) (tp.Container, error) {
	if dh.DockerClient == nil {
		return tp.Container{}, errors.New("no docker client")
	}

	inspect, err := dh.DockerClient.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return tp.Container{}, err
	}

	container := tp.Container{}

	// == container base == //

	container.ContainerID = inspect.ID
	container.ContainerName = strings.TrimLeft(inspect.Name, "/")

	container.NamespaceName = "Unknown"
	container.EndPointName = "Unknown"

	containerLabels := inspect.Config.Labels
	if _, ok := containerLabels["io.kubernetes.pod.namespace"]; ok { // kubernetes
		if val, ok := containerLabels["io.kubernetes.pod.namespace"]; ok {
			container.NamespaceName = val
		}
		if val, ok := containerLabels["io.kubernetes.pod.name"]; ok {
			container.EndPointName = val
		}
	}

	container.MergedDir = inspect.GraphDriver.Data["MergedDir"]

	// == //

	pid := strconv.Itoa(inspect.State.Pid)

	if data, err := os.Readlink("/proc/" + pid + "/ns/pid"); err == nil {
		if _, err := fmt.Sscanf(data, "pid:[%d]\n", &container.PidNS); err != nil {
			fmt.Printf("Unable to get PidNS (%s, %s, %s)", containerID, pid, err.Error())
		}
	}

	if data, err := os.Readlink("/proc/" + pid + "/ns/mnt"); err == nil {
		if _, err := fmt.Sscanf(data, "mnt:[%d]\n", &container.MntNS); err != nil {
			fmt.Printf("Unable to get MntNS (%s, %s, %s)", containerID, pid, err.Error())
		}
	}

	// == //

	/*

		fmt.Printf("Docker container ID: %s \n", container.ContainerID)
		fmt.Printf("Docker container Name: %s \n", container.ContainerName)
		fmt.Printf("Docker container Namespace: %s \n", container.NamespaceName)
		fmt.Printf("Docker container EndpointName: %s \n", container.EndPointName)
		fmt.Printf("Docker container PidNS: %s \n", container.PidNS)
		fmt.Printf("Docker container MntNS: %s \n", container.MntNS)
		fmt.Println("========= Docker container information =========")
		fmt.Println("")

	*/
	return container, nil
}

// GetEventChannel Function
func (dh *DockerHandler) GetEventChannel() <-chan events.Message {
	if dh.DockerClient != nil {
		event, _ := dh.DockerClient.Events(context.Background(), types.EventsOptions{})
		return event
	}

	return nil
}

// =================== //
// == Docker Events == //
// =================== //

// GetAlreadyDeployedDockerContainers Function
func (dm *KrsieDaemon) GetAlreadyDeployedDockerContainers() {
	// check if Docker exists
	if Docker == nil {
		return
	}

	if containerList, err := Docker.DockerClient.ContainerList(context.Background(), types.ContainerListOptions{}); err == nil {
		for _, dcontainer := range containerList {
			// get container information from docker client
			container, err := Docker.GetContainerInfo(dcontainer.ID)
			if err != nil {
				continue
			}

			if container.ContainerID == "" {
				continue
			}

			if dcontainer.State == "running" {
				dm.ContainersLock.Lock()
				if _, ok := dm.Containers[container.ContainerID]; !ok {
					dm.Containers[container.ContainerID] = container
					dm.ContainersLock.Unlock()
				} else if dm.Containers[container.ContainerID].PidNS == 0 && dm.Containers[container.ContainerID].MntNS == 0 {
					// this entry was updated by kubernetes before docker detects it
					// thus, we here use the info given by kubernetes instead of the info given by docker

					container.NamespaceName = dm.Containers[container.ContainerID].NamespaceName
					container.EndPointName = dm.Containers[container.ContainerID].EndPointName
					container.Labels = dm.Containers[container.ContainerID].Labels

					container.ContainerName = dm.Containers[container.ContainerID].ContainerName
					container.ContainerImage = dm.Containers[container.ContainerID].ContainerImage

					dm.Containers[container.ContainerID] = container
					dm.ContainersLock.Unlock()

					dm.EndPointsLock.Lock()
					for idx, endPoint := range dm.EndPoints {
						if endPoint.NamespaceName == container.NamespaceName && endPoint.EndPointName == container.EndPointName {
							// update containers
							if !ContainsElement(endPoint.Containers, container.ContainerID) {
								dm.EndPoints[idx].Containers = append(dm.EndPoints[idx].Containers, container.ContainerID)
							}
							break
						}
					}
					dm.EndPointsLock.Unlock()
				} else {
					dm.ContainersLock.Unlock()
					continue
				}

				/*
					if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
						// update NsMap
						dm.SystemMonitor.AddContainerIDToNsMap(container.ContainerID, container.PidNS, container.MntNS)
					}
				*/

				fmt.Printf("Detected a container (added/%s) \n", container.ContainerID[:12])
			}
		}
	}
}

// UpdateDockerContainer Function
func (dm *KrsieDaemon) UpdateDockerContainer(containerID, action string) {
	// check if Docker exists
	if Docker == nil {
		return
	}

	container := tp.Container{}

	if action == "start" {
		var err error

		// get container information from docker client
		container, err = Docker.GetContainerInfo(containerID)
		if err != nil {
			return
		}

		if container.ContainerID == "" {
			return
		}

		dm.ContainersLock.Lock()
		if _, ok := dm.Containers[containerID]; !ok {
			dm.Containers[containerID] = container
			dm.ContainersLock.Unlock()
		} else if dm.Containers[containerID].PidNS == 0 && dm.Containers[containerID].MntNS == 0 {
			// this entry was updated by kubernetes before docker detects it
			// thus, we here use the info given by kubernetes instead of the info given by docker

			container.NamespaceName = dm.Containers[containerID].NamespaceName
			container.EndPointName = dm.Containers[containerID].EndPointName
			container.Labels = dm.Containers[containerID].Labels

			container.ContainerName = dm.Containers[containerID].ContainerName
			container.ContainerImage = dm.Containers[containerID].ContainerImage

			dm.Containers[containerID] = container
			dm.ContainersLock.Unlock()

			dm.EndPointsLock.Lock()
			for idx, endPoint := range dm.EndPoints {
				if endPoint.NamespaceName == container.NamespaceName && endPoint.EndPointName == container.EndPointName {
					// update containers
					if !ContainsElement(endPoint.Containers, container.ContainerID) {
						dm.EndPoints[idx].Containers = append(dm.EndPoints[idx].Containers, container.ContainerID)
					}
					break
				}
			}
			dm.EndPointsLock.Unlock()
		} else {
			dm.ContainersLock.Unlock()
			return
		}

		/*
			if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
				// update NsMap
				dm.SystemMonitor.AddContainerIDToNsMap(containerID, container.PidNS, container.MntNS)
			}
		*/

		fmt.Printf("Detected a container (added/%s)", containerID[:12])

	} else if action == "stop" || action == "destroy" {
		// case 1: kill -> die -> stop
		// case 2: kill -> die -> destroy
		// case 3: destroy

		dm.ContainersLock.Lock()
		container, ok := dm.Containers[containerID]
		if !ok {
			dm.ContainersLock.Unlock()
			return
		}
		delete(dm.Containers, containerID)
		dm.ContainersLock.Unlock()

		dm.EndPointsLock.Lock()
		for idx, endPoint := range dm.EndPoints {
			if endPoint.NamespaceName == container.NamespaceName && endPoint.EndPointName == container.EndPointName {
				// update containers
				for idxC, containerID := range endPoint.Containers {
					if containerID == container.ContainerID {
						dm.EndPoints[idx].Containers = append(dm.EndPoints[idx].Containers[:idxC], dm.EndPoints[idx].Containers[idxC+1:]...)
						break
					}
				}

				break
			}
		}
		dm.EndPointsLock.Unlock()

		/*
			if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
				// update NsMap
				dm.SystemMonitor.DeleteContainerIDFromNsMap(containerID)
			}

		*/
		fmt.Printf("Detected a container (removed/%s)", containerID[:12])
	}
}

// MonitorDockerEvents Function
func (dm *KrsieDaemon) MonitorDockerEvents() {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

	// check if Docker exists
	if Docker == nil {
		return
	}

	fmt.Printf("Started to monitor Docker events")

	EventChan := Docker.GetEventChannel()

	for {
		select {
		case <-StopChan:
			return

		case msg, valid := <-EventChan:
			if !valid {
				continue
			}

			// if message type is container
			if msg.Type == "container" {
				dm.UpdateDockerContainer(msg.ID, msg.Action)
			}
		}
	}
}
