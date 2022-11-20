* For monitoringpart, you can user the command below to run tracee-ebpf in another shell
 !! note that, it requires docker version over 20.10 for the flag "--cgroupns"

  docker run \
  --name tracee --rm -it \
  --log-driver syslog \
  --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
  aquasec/tracee:latest \
  trace

* Then our log will be stored at /var/log/syslog file. It will be parsed in a program written in golang
