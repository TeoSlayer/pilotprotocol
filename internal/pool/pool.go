package pool

import "sync"

// Packet buffers sized for typical tunnel frames.
const (
	SmallBufSize = 4096               // for IPC messages, small packets
	LargeBufSize = 65535 + 38         // max payload + tunnel magic(4) + header(34)
)

var (
	smallPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, SmallBufSize)
			return &b
		},
	}
	largePool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, LargeBufSize)
			return &b
		},
	}
)

// GetSmall returns a small buffer from the pool.
func GetSmall() *[]byte {
	return smallPool.Get().(*[]byte)
}

// PutSmall returns a small buffer to the pool.
func PutSmall(b *[]byte) {
	if b == nil || cap(*b) < SmallBufSize {
		return
	}
	*b = (*b)[:SmallBufSize]
	smallPool.Put(b)
}

// GetLarge returns a large buffer from the pool.
func GetLarge() *[]byte {
	return largePool.Get().(*[]byte)
}

// PutLarge returns a large buffer to the pool.
func PutLarge(b *[]byte) {
	if b == nil || cap(*b) < LargeBufSize {
		return
	}
	*b = (*b)[:LargeBufSize]
	largePool.Put(b)
}
