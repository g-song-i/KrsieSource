package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// SecuritySpec Structure
type SecuritySpec struct {
	Selector SelectorType `yaml:"selector"`

	Name    string `yaml:"syscall,omitempty"`
	LsmName string `yaml:"lsmHook,omitempty"`

	Conditions MatchConditionsType `yaml:"conditions,omitempty"`

	// To distinguish among pods
	// Tags    []string `yaml:"tags"`
	Message string `yaml:"message,omitempty"`
}

type SelectorType struct {
	MatchLabels map[string]string `yaml:"matchLabels,omitempty"`
	// Identities  []string          `json:"identities,omitempty"`
}

type MatchConditionsType struct {
	Parameter string `yaml:"parameter,omitempty"`
	Operator  string `yaml:"operator,omitempty"`
	Value     string `yaml:"value,omitempty"`

	Action string `yaml:"action"`
}

func main() {
	fmt.Println("START TO READ SYSLOG")

	duration, _ := time.ParseDuration("5s")
	ticker := time.NewTicker(duration)

	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			read_file()
			fmt.Println("received log successfully")
		}
	}
}

func read_file() {

	lsm_hooks := []string{"security_bprm_check", "security_bprm_creds_for_exec", "security_file_mprotect", "security_inode_mkdir", "security_locked_down", "security_path_chmod_fix", "security_path_mkdir", "security_ptrace_access_check", "security_ptrace_traceme", "security_socket_accept", "security_socket_bind", "security_socket_connect", "security_socket_create", "security_socket_listen", "security_socket_post_create", "security_socket_recvmsg", "security_task_alloc", "security_task_fix_setgid", "security_task_fix_setuid", "security_task_free", "security_task_kill", "security_vm_enough_memory"}

	log_string, err := os.Open("/root/.gvm/pkgsets/go1.19/source/KrsieSource/sample/mylogs.txt")

	if err != nil {
		log.Fatal(err)
	}

	defer log_string.Close()
	// fmt.Println(str_log)

	scanner := bufio.NewScanner(log_string)

	for scanner.Scan() {
		s := scanner.Text()
		for _, hook := range lsm_hooks {
			MntNS := "1234"
			isContains := strings.Contains(s, hook)
			if isContains == true {
				// fmt.Println("LINES: \n", s)
				s_list := strings.Fields(s)
				pid_num := s_list[3]
				// fmt.Println("PID: \n", pid_num)

				pathExists := path_check(pid_num)
				if pathExists == false {
					break
				}

				if data, err := os.Readlink("/proc/" + pid_num + "/ns/mnt"); err == nil {
					if _, err := fmt.Sscanf(data, "mnt:[%d]\n", MntNS); err != nil {
						err.Error()
					}
				}

				policyExists := policy_check(MntNS)

				if policyExists == true {
					create_policy(s, MntNS, hook)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

func match_mntns(pid_num string) string {

	cmd := exec.Command("stat", "-Lc", "'%i'", "/proc/"+pid_num+"/ns/mnt")
	stdout, err := cmd.Output()

	if err != nil {
		fmt.Println(err.Error())
	}

	mnt_ns := string(stdout)

	return mnt_ns
}

func path_check(pid_num string) bool {

	// pid_string := strconv.Itoa(pid_num)
	if _, err := os.Stat("/proc/" + pid_num + "/ns/mnt"); !os.IsNotExist(err) {
		// fmt.Println("the process has mnt ns")
		return true
	}

	return false
}

func policy_check(mnt_ns string) bool {

	goPath := os.Getenv("GOPATH")
	policyPath := goPath + "/../source/KrsieSource/policy/"

	files, err := ioutil.ReadDir(policyPath)
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		fileName := f.Name()
		mnt_noline := strings.TrimSuffix(mnt_ns, "\n")
		mnt_nochar := strings.Trim(mnt_noline, "'")
		mnt_int, err := strconv.Atoi(mnt_nochar)

		if err != nil {
			fmt.Println(err)
		}
		mnt_hex := fmt.Sprintf("%x", mnt_int)
		isContains := strings.Contains(mnt_hex, fileName)
		fmt.Println("MNTNS: ", mnt_hex)
		if isContains == true {
			fmt.Println("monitored container is founded")
			return true
		}

		// fmt.Println("there is no monitored container")
	}

	return false
}

func create_policy(line string, mnt_ns string, hook string) {

	bprm_check := "security_bprm_check"

	if hook == bprm_check {
		index := strings.Index(line, "inode:")
		inode := line[index:]

		policy := SecuritySpec{
			Selector: SelectorType{
				MatchLabels: map[string]string{
					"group": "group-gid",
				},
			},
			Name:    "execve",
			LsmName: bprm_check,
			Conditions: MatchConditionsType{
				Parameter: "data.inode",
				Operator:  "==",
				Value:     inode,
				Action:    "Deny",
			},
			Message: "Deny" + bprm_check + " for container MNT NS:" + mnt_ns,
		}

		data, err := yaml.Marshal(&policy)
		fmt.Println(data)

		if err != nil {
			log.Fatal(err)
		}
	}

}
