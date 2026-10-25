package app

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type systemMetrics struct {
	CPUPercent       *float64 `json:"cpu_percent"`
	CPUCores         float64  `json:"cpu_cores"`
	MemoryBytes      *uint64  `json:"memory_bytes"`
	MemoryLimitBytes *uint64  `json:"memory_limit_bytes"`
	Source           string   `json:"source"`
}
type systemSampler struct {
	mu       sync.Mutex
	previous uint64
	at       time.Time
}

func readMetric(path string) string {
	b, e := os.ReadFile(path)
	if e != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
func metricCounter(value, key string) (uint64, bool) {
	for _, line := range strings.Split(value, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == key {
			v, e := strconv.ParseUint(fields[1], 10, 64)
			return v, e == nil
		}
	}
	return 0, false
}
func cpuCapacity(quota string, fallback float64) float64 {
	fields := strings.Fields(quota)
	if len(fields) == 2 && fields[0] != "max" {
		q, e1 := strconv.ParseFloat(fields[0], 64)
		p, e2 := strconv.ParseFloat(fields[1], 64)
		if e1 == nil && e2 == nil && q > 0 && p > 0 {
			return min(fallback, q/p)
		}
	}
	return fallback
}
func (s *systemSampler) sample() systemMetrics {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	out := systemMetrics{CPUCores: float64(runtime.NumCPU()), Source: "process"}
	usage, available := metricCounter(readMetric("/sys/fs/cgroup/cpu.stat"), "usage_usec")
	if available {
		usage *= 1000
		out.Source = "container"
		out.CPUCores = cpuCapacity(readMetric("/sys/fs/cgroup/cpu.max"), out.CPUCores)
	} else {
		var r syscall.Rusage
		if syscall.Getrusage(syscall.RUSAGE_SELF, &r) == nil {
			usage = uint64(r.Utime.Sec+r.Stime.Sec)*1e9 + uint64(r.Utime.Usec+r.Stime.Usec)*1000
			available = true
		}
	}
	if available && !s.at.IsZero() && usage >= s.previous && now.After(s.at) && out.CPUCores > 0 {
		percent := float64(usage-s.previous) / float64(now.Sub(s.at)) * 100 / out.CPUCores
		out.CPUPercent = &percent
	}
	if available {
		s.previous = usage
		s.at = now
	}
	if memory, e := strconv.ParseUint(readMetric("/sys/fs/cgroup/memory.current"), 10, 64); e == nil {
		out.MemoryBytes = &memory
		if limit, e := strconv.ParseUint(readMetric("/sys/fs/cgroup/memory.max"), 10, 64); e == nil {
			out.MemoryLimitBytes = &limit
		}
	} else if memory, ok := metricCounter(readMetric("/proc/self/status"), "VmRSS:"); ok {
		memory *= 1024
		out.MemoryBytes = &memory
	}
	return out
}
