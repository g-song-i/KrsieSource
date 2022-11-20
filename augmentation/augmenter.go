package main

import (
    "fmt"
    "io/ioutil"
    "os"
    "time"
    "strings"
)

func main() {
    fmt.Println("START TO READ SYSLOG")

    duration, _ := time.ParseDuration("60s")
    ticker := time.NewTicker(duration)

    defer ticker.Stop()
    for {
	    select {
	    case <-ticker.C:
		    log_str := read_file()
		    fmt.Println("received log successfully")
		    parse_event(log_str)
	    }
    }
}

func read_file() string {
    log_string, err := os.Open("/var/log/syslog")
    content, err := ioutil.ReadAll(log_string)

    if err != nil {
        panic(err)
    }

    str_log := string(content)
    // fmt.Println(str_log)


    return str_log
}

func parse_event(log_string string) {

    lsm_hooks := []string{"security_bprm_check", "security_bprm_creds_for_exec", "security_file_mprotect", "security_inode_mkdir", "security_locked_down", "security_path_chmod_fix", "security_path_mkdir", "security_ptrace_access_check", "security_ptrace_traceme", "security_socket_accept", "security_socket_bind", "security_socket_connect", "security_socket_create", "security_socket_listen", "security_socket_post_create", "security_socket_recvmsg", "security_task_alloc", "security_task_fix_setgid", "security_task_fix_setuid", "security_task_free", "security_task_kill", "security_vm_enough_memory"}

    string_log := string(log_string)
    for _, line := range string_log {
	string_line := string(line)
	for _, hook := range lsm_hooks {
	    idxFind := strings.Index(string_line, hook)
            left := strings.LastIndex(string_line[:idxFind], "\n")
	    right := strings.Index(string_line[idxFind:], "\n")

	    fmt.Println(string_line[left : idxFind+right])
        }
    }
}

func alert_and_recommend() {
}
