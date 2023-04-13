// This program demonstrates attaching an eBPF program to a control group.
// The eBPF program will be attached as an egress filter,
// receiving an `__sk_buff` pointer for each outgoing packet.
// It prints the count of total packets every second.
package main

import (
	"bufio"
	"errors"
	"log"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf cgroup_skb.c -- -I../headers

// func init(){
// 	go startProxy()
// }

type Dest_info struct {
	Dest_ip   uint32
	Dest_port uint32
}

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Get the first-mounted cgroupv2 path.
	cgroupPath, err := detectCgroupPath()
	if err != nil {
		log.Fatal(err)
	}

	println("cgroup path: ", cgroupPath)

	// Link the count_egress_packets program to the cgroup.
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.CountEgressPackets,
	})

	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	c4, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.K_connect4,
	})

	if err != nil {
		log.Fatal(err)
	}
	defer c4.Close()

	gp4, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCgroupInet4GetPeername,
		Program: objs.K_getpeername4,
	})

	if err != nil {
		log.Fatal(err)
	}
	defer gp4.Close()

	log.Println("Counting packets...")

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()


	objs.PortMapping.Update(uint32(1),Dest_info{Dest_ip: 10,Dest_port: 11},)
	for range ticker.C {
		var value uint64
		if err := objs.PktCount.Lookup(uint32(0), &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}

		var dest Dest_info
		var key uint32 = 1

		// iter := objs.PortMapping.Iterate()
		// for iter.Next(&key,&dest){
		// 	log.Printf("Key: %v || Value: %v",key,dest)
		// }

		if err := objs.PortMapping.Lookup(key, &dest); err != nil {
			log.Printf("reading Port map: %v", err)
		}else{
			log.Printf("Value for key:[%v]: %v",key,dest)
		}

		// log.Printf("number of packets: %d\n", value)
	}

}

// detectCgroupPath returns the first-found mount point of type cgroup2
// and stores it in the cgroupPath global variable.
func detectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// example fields: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroup2 not mounted")
}
