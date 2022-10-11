// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor
// Modified by: Songi Gwak, Sept 2022

package install

import (
	_ "embed"
	"log"

	"sigs.k8s.io/yaml"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

//go:embed KrsiePolicy.yaml
var crdBytes []byte

// GetCRD returns the generated CRD. The CRD is generated by controller-gen
// which is embedded at compile time using go:embed.
func GetCRD() {
	krise := apiextensionsv1.CustomResourceDefinition{}
	err := yaml.Unmarshal(crdBytes, &krise)
	if err != nil {
		log.Fatal("Error unmarshalling pregenerated CRD")
	}
}
