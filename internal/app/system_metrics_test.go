package app

import (
	"testing"
	"time"
)

func TestSystemMetricParsing(t *testing.T) {
	if usage, ok := metricCounter("usage_usec 1500\nuser_usec 1000", "usage_usec"); !ok || usage != 1500 {
		t.Fatal("bad CPU counter")
	}
	if cpuCapacity("50000 100000", 8) != 0.5 || cpuCapacity("max 100000", 8) != 8 {
		t.Fatal("bad CPU quota")
	}
	sampler := &systemSampler{}
	sampler.sample()
	time.Sleep(time.Millisecond)
	v := sampler.sample()
	if v.CPUCores <= 0 || v.CPUPercent == nil || *v.CPUPercent < 0 {
		t.Fatal("CPU metrics unavailable")
	}
}
