from argparse import ArgumentParser
import logging
import argparse
import re
from bcc import BPF
import datetime
import inspect
import sys
VERSION = "1.0"
DESCRIPTION = "Kubernetes dynamic eBPF policy security"
logger = logging.getLogger("log")

def all_event(data, l=None):
    res = ""
    if l==None:   
        for i in dir(data):
            if (not i.startswith('_')):
                res += "{}={} ".format(i,getattr(data,i))
    else:
        for i in l:
            res += "{}={} ".format(i,getattr(data,i))
    return res

def run(file_path):
    try:
        fp = open(file_path, "r")
        bpf_prog = fp.read()
        fp.close()
    except FileNotFoundError:
        print("Please check the path.")

    b = BPF(text=bpf_prog)
    def print_event(cpu, data, size):
        """
        Print event data when a kill signal is about to be
        sent.
        """
        event = b["events"].event(data)
        print(
            datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"), " [{}] ".format(lsm_hook), all_event(event)
        )

    b["events"].open_perf_buffer(print_event)
    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

def main():
    description = DESCRIPTION
    opt = argparse.ArgumentParser(
            description=description
        )

    opt.add_argument(
        '-f', '--file', type=str,
        # required=True,
        help='BPF file in C format'
    )
    args = opt.parse_args()
    run(args.file)

if __name__ == "__main__":
    sys.exit(main())