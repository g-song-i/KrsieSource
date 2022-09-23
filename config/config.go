// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package config

import (
	"fmt"
	"os"
	"strings"

	"flag"

	"github.com/spf13/viper"
)

// KrsieConfig Structure
type KrsieConfig struct {
	Cluster string // Cluster name to use for feeds
	Host    string // Host name to use for feeds

	GRPC string // gRPC Port to use
}

// GlobalCfg Global configuration for Kubearmor
var GlobalCfg KrsieConfig

// ConfigCluster Cluster name key
const ConfigCluster string = "cluster"

// ConfigHost Host name key
const ConfigHost string = "host"

// ConfigGRPC GRPC Port key
const ConfigGRPC string = "gRPC"

// ConfigK8sEnv VM key
const ConfigK8sEnv string = "k8s"

func readCmdLineParams() {
	hostname, _ := os.Hostname()
	clusterStr := flag.String(ConfigCluster, "default", "cluster name")
	hostStr := flag.String(ConfigHost, strings.Split(hostname, ".")[0], "host name")

	grpcStr := flag.String(ConfigGRPC, "32767", "gRPC port number")

	k8sEnvB := flag.Bool(ConfigK8sEnv, true, "is k8s env?")

	flags := []string{}
	flag.VisitAll(func(f *flag.Flag) {
		kv := fmt.Sprintf("%s:%v", f.Name, f.Value)
		flags = append(flags, kv)
	})
	fmt.Printf("Arguments [%s]", strings.Join(flags, " "))

	flag.Parse()

	viper.SetDefault(ConfigCluster, *clusterStr)
	viper.SetDefault(ConfigHost, *hostStr)

	viper.SetDefault(ConfigGRPC, *grpcStr)
	viper.SetDefault(ConfigK8sEnv, *k8sEnvB)
}

// LoadConfig Load configuration
func LoadConfig() error {
	// Read configuration from command line
	readCmdLineParams()

	// Read configuration from env var
	// Note that the env var has to be set in uppercase for e.g, CLUSTER=xyz ./kubearmor
	viper.AutomaticEnv()

	// Read configuration from config file
	cfgfile := os.Getenv("KUBEARMOR_CFG")
	if cfgfile == "" {
		cfgfile = "kubearmor.yaml"
	}
	if _, err := os.Stat(cfgfile); err == nil {
		fmt.Printf("setting config from file [%s]", cfgfile)
		viper.SetConfigFile(cfgfile)
		err := viper.ReadInConfig()
		if err != nil {
			return err
		}
	}

	GlobalCfg.Cluster = viper.GetString(ConfigCluster)
	GlobalCfg.Host = viper.GetString(ConfigHost)

	GlobalCfg.GRPC = viper.GetString(ConfigGRPC)

	fmt.Printf("Configuration [%+v]", GlobalCfg)
	fmt.Printf("Final Configuration [%+v]", GlobalCfg)

	return nil
}
