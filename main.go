// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor
package main

import (
	cfg "github.com/g-song-i/KrsieSource/config"
	core "github.com/g-song-i/KrsieSource/core"
	install "github.com/g-song-i/KrsieSource/install"

	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	if os.Geteuid() != 0 {
		fmt.Printf("Need to have root privileges to run %s\n", os.Args[0])
		return
	}

	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		fmt.Printf(err.Error())
		return
	}

	if err := os.Chdir(dir); err != nil {
		fmt.Printf(err.Error())
		return
	}

	if finfo, err := os.Stat(os.Args[0]); err == nil {
		stat := finfo.Sys().(*syscall.Stat_t)
		fmt.Printf("Build Time: %v", time.Unix(int64(stat.Ctim.Sec), int64(stat.Ctim.Nsec)))
	}

	krsieCRD := install.GetCRD()
	if krsieCRD == nil {
		fmt.Println("error to create CRD ")
	}

	if err := cfg.LoadConfig(); err != nil {
		fmt.Printf(err.Error())
		return
	}

	core.Krsie()
}
