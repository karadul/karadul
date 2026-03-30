package coordinator

import (
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// cpuSampler estimates process CPU usage by sampling getrusage deltas.
// No cgo required — uses syscall.Getrusage which works on macOS and Linux.
type cpuSampler struct {
	usage  atomic.Value // stores float64 (0–100)
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// newCPUSampler starts a background sampler that updates every interval.
func newCPUSampler(interval time.Duration) *cpuSampler {
	s := &cpuSampler{
		stopCh: make(chan struct{}),
	}
	s.usage.Store(float64(0))

	s.wg.Add(1)
	go s.run(interval)
	return s
}

func (s *cpuSampler) run(interval time.Duration) {
	defer s.wg.Done()

	prevWall := time.Now()
	prevCPU := processCPUTimeNanos()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			curCPU := processCPUTimeNanos()

			wallNanos := now.Sub(prevWall).Nanoseconds()
			cpuNanos := curCPU - prevCPU

			if wallNanos > 0 {
				pct := float64(cpuNanos) / float64(wallNanos) * 100
				if pct < 0 {
					pct = 0
				}
				if pct > 100 {
					pct = 100
				}
				s.usage.Store(pct)
			}

			prevWall = now
			prevCPU = curCPU

		case <-s.stopCh:
			return
		}
	}
}

// CPUUsage returns the latest CPU usage estimate as a percentage (0–100).
func (s *cpuSampler) CPUUsage() float64 {
	v, _ := s.usage.Load().(float64)
	return v
}

// Stop terminates the background sampling goroutine.
func (s *cpuSampler) Stop() {
	close(s.stopCh)
	s.wg.Wait()
}

// processCPUTimeNanos returns total user+system CPU nanoseconds for the
// current process using getrusage.
func processCPUTimeNanos() int64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	// Utime and Stime are timeval structs (seconds + microseconds).
	userNs := int64(ru.Utime.Sec)*1e9 + int64(ru.Utime.Usec)*1e3
	sysNs := int64(ru.Stime.Sec)*1e9 + int64(ru.Stime.Usec)*1e3
	return userNs + sysNs
}
