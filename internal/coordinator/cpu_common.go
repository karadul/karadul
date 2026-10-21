package coordinator

import (
	"sync"
	"sync/atomic"
	"time"
)

type cpuSampler struct {
	usage  atomic.Value
	stopCh chan struct{}
	wg     sync.WaitGroup
}

func newCPUSampler(interval time.Duration) *cpuSampler {
	s := &cpuSampler{stopCh: make(chan struct{})}
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

func (s *cpuSampler) CPUUsage() float64 {
	v, _ := s.usage.Load().(float64)
	return v
}

func (s *cpuSampler) Stop() {
	close(s.stopCh)
	s.wg.Wait()
}
