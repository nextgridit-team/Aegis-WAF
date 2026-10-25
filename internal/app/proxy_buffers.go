package app

import "sync"

const proxyBufferBytes = 32 << 10

type proxyBufferPool struct{ buffers sync.Pool }

func (p *proxyBufferPool) Get() []byte {
	if value := p.buffers.Get(); value != nil {
		return value.(*[proxyBufferBytes]byte)[:]
	}
	return make([]byte, proxyBufferBytes)
}
func (p *proxyBufferPool) Put(buffer []byte) {
	if len(buffer) != proxyBufferBytes {
		return
	}
	// Do not retain upstream response content while the buffer is idle.
	clear(buffer)
	p.buffers.Put((*[proxyBufferBytes]byte)(buffer))
}

var forwardingBuffers proxyBufferPool
