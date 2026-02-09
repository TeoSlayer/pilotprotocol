package pool

import "sync"

// Packet buffers sized for typical tunnel frames.
const (
	SmallBufSize   = 8192             // for IPC messages, small packets (matches MaxSegmentSize)
	LargeBufSize   = 65535 + 38       // max payload + tunnel magic(4) + header(34)
	SegmentBufSize = 8192             // segment-sized buffers for retransmission/OOO tracking
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
	segmentPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, SegmentBufSize)
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

// GetSegment returns a segment-sized buffer from the pool.
func GetSegment() *[]byte {
	return segmentPool.Get().(*[]byte)
}

// PutSegment returns a segment-sized buffer to the pool.
func PutSegment(b *[]byte) {
	if b == nil || cap(*b) < SegmentBufSize {
		return
	}
	*b = (*b)[:SegmentBufSize]
	segmentPool.Put(b)
}
