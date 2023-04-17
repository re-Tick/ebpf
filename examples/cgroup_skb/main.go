// This program demonstrates attaching an eBPF program to a control group.
// The eBPF program will be attached as an egress filter,
// receiving an `__sk_buff` pointer for each outgoing packet.
// It prints the count of total packets every second.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf cgroup_skb.c -- -I../headers

func init() {
	bootProxies()
	log.Println("The running ports: ", runningPorts)
}

type Dest_info struct {
	Dest_ip   uint32
	Dest_port uint32
}

type Bpf_spin_lock struct{ Val uint32 }

type Vaccant_port struct {
	Port uint32
	// Occupied bool
	Lock Bpf_spin_lock
}

var objs = bpfObjects{}

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	// objs := bpfObjects{}
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

	objs.PortMapping.Update(uint32(1), Dest_info{Dest_ip: 10, Dest_port: 11}, ebpf.UpdateAny)

	arr, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 2,
	})
	if err != nil {
		panic(err)
	}
	defer arr.Close()

	first := []uint32{4, 5}
	fmt.Printf("sizeof an element in percpu: %v", unsafe.Sizeof(first))
	if err := arr.Put(uint32(0), first); err != nil {
		panic(err)
	}

	second := []uint32{2, 8}
	if err := arr.Put(uint32(1), second); err != nil {
		panic(err)
	}

	var values []uint32
	if err := arr.Lookup(uint32(0), &values); err != nil {
		panic(err)
	}
	fmt.Printf("First two values: %v for typesof: %T\n", values[:2], arr)

	for i, v := range runningPorts {
		log.Printf("setting the vPorts at i: %v and port: %v, ncpus: %v, sizeof(vaccantPorts): %v", i, v, runtime.NumCPU(), unsafe.Sizeof(Vaccant_port{Port: v}))
		inf, err := objs.VaccantPorts.Info()
		err = objs.VaccantPorts.Update(uint32(i), Vaccant_port{Port: v}, ebpf.UpdateLock)

		// err := objs.VaccantPorts.Update(uint32(i), []Vaccant_port{{Port: v, Occupied: false}}, ebpf.UpdateAny)
		// ports := []uint32{}
		// for i := 0; i < runtime.NumCPU(); i++ {
		// 	ports = append(ports, v)
		// }
		// err := objs.VaccantPorts.Put(uint32(i), ports)

		// err := objs.VaccantPorts.Put(uint32(i), []Vaccant_port{{Port: v, Occupied: false}, {Port: v, Occupied: false}})

		if err != nil {
			log.Printf("failed to update the vaccantPorts array at userspace. error: %v", err)
		}
		log.Printf("info about VaccantPorts: %v", inf)
	}
	for range ticker.C {
		var value uint64
		if err := objs.PktCount.Lookup(uint32(0), &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}

		var port = Vaccant_port{}
		var all_cpu_value []uint32
		if err := objs.VaccantPorts.Lookup(uint32(0), &all_cpu_value); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		for cpuid, cpuvalue := range all_cpu_value {
			log.Printf("%s called %d times on CPU%v\n", "connect4", cpuvalue, cpuid)
		}
		log.Printf("reading map: %v", port)

		// var dest Dest_info
		// var key uint32 = 1

		// iter := objs.PortMapping.Iterate()
		// for iter.Next(&key,&dest){
		// 	log.Printf("Key: %v || Value: %v",key,dest)
		// }

		// if err := objs.PortMapping.Lookup(key, &dest); err != nil {
		// 	log.Printf("/proxy: reading Port map: %v", err)
		// } else {
		// 	log.Printf("/proxy: Value for key:[%v]: %v", key, dest)
		// }

		// objs.
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
