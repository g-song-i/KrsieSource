package core

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// #include <stdlib.h>
import "C"

const (
	symbol  = "readline"
	binPath = "/bin/bash"
)

type Event struct {
	PID uint32
}

// ======================= //
// == Bpf Enforcer == //
// ======================= //

func (dm *KrsieDaemon) Bpfenforcer() {

	// preparation
	/*
		path, err := os.Getwd()
		if err != nil {
			fmt.Println("error to get path", err)
		}
		fmt.Printf("Current working path: %s \n", path)
	*/

	gopath := os.Getenv("GOPATH")
	python_path := gopath + "/../source/KrsieSource/core/"

	for _, endPoint := range dm.EndPoints {
		for _, container := range dm.Containers {
			enforcePath := ""
			if len(endPoint.SecurityPolicies) > 0 {

				for idx, secPolicy := range endPoint.SecurityPolicies {

					syscall_name := secPolicy.Spec.Name
					lsm_name := secPolicy.Spec.LsmName

					condition_parameter := secPolicy.Spec.Conditions[0].Parameter
					condition_operator := secPolicy.Spec.Conditions[0].Operator
					condition_value := secPolicy.Spec.Conditions[0].Value
					condition_action := secPolicy.Spec.Conditions[0].Action

					// fmt.Println("syscall name %s", syscall_name)
					// fmt.Println("lsm name %s", lsm_name)

					action := ""
					inverse := ""

					if condition_action == "Allow" {
						action = "0"
						inverse = "-1"
					} else if condition_action == "Deny" {
						action = "-1"
						inverse = "0"
					}

					endpoint_containerID := endPoint.Containers
					containerID := container.ContainerID

					if !ContainsElement(endpoint_containerID, containerID) {
						continue
					}

					// mountNs := strconv.FormatInt(container.MntNS, 16)
					mountNs := fmt.Sprintf("%x", container.MntNS)
					mountNs = "0x" + mountNs
					condition := condition_parameter + condition_operator + condition_value

					file, err := os.Open(gopath + "/../source/KrsieSource/bpf/" + lsm_name + ".c")
					if err != nil {
						fmt.Println("error occur when open bpf file")
					}
					defer file.Close()

					scanner := bufio.NewScanner(file)

					newFilePath := gopath + "/../source/KrsieSource/policy/" + syscall_name + "_" + lsm_name + "_" + mountNs + "_" + strconv.Itoa(idx) + ".c"

					enforcePath = newFilePath

					new_policy, err := os.Create(newFilePath)
					if err != nil {
						fmt.Println("error occur when open file for writing new policy")
					}
					defer new_policy.Close()

					raw := ""

					for scanner.Scan() {
						line := scanner.Text()
						if err == io.EOF {
							break
						}
						if err != nil {
							fmt.Println("line read err", err)
						}

						removalLine := line
						if strings.Contains(removalLine, "CONDITIONS") {
							removalLine = strings.ReplaceAll(removalLine, "CONDITIONS", condition)
						}
						if strings.Contains(removalLine, "ACTION") {
							removalLine = strings.ReplaceAll(removalLine, "ACTION", action)
						}
						if strings.Contains(line, "INVERSE") {
							removalLine = strings.ReplaceAll(removalLine, "INVERSE", inverse)
						}
						if strings.Contains(line, "MOUNT_NS_ID") {
							removalLine = strings.ReplaceAll(removalLine, "MOUNT_NS_ID", mountNs)
						}

						// fmt.Printf("%s", removalLine)
						sentence := removalLine + "\n"
						new_policy.WriteString(sentence)
						raw += sentence
					}
					go RunEnforce(python_path, enforcePath)
				}
			}

		}
	}
}

func RunEnforce(pythonPath string, policyPath string) {

	cmd := exec.Command("python3", pythonPath+"main.py", "-f", policyPath)
	fmt.Printf("policy enforcement start %s \n", policyPath)
	cmd.Stdout = os.Stdout

	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}
