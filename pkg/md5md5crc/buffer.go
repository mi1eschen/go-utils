package md5md5crc

type buffer struct {
	buf       []byte // contents are the bytes buf[off : len(buf)]
	off       int    // read at &buf[off], write at &buf[len(buf)]
	originCap int
}

func newBuffer(bufSize int) *buffer {
	return &buffer{
		buf:       make([]byte, 0, bufSize),
		originCap: bufSize,
	}
}

func (b *buffer) Write(p []byte) (n int, err error) {
	if len(b.buf)+len(p) > cap(b.buf) {
		b.grow()
	}

	m, _ := b.tryGrowByReslice(len(p))
	n = copy(b.buf[m:], p)
	return n, nil
}

func (b *buffer) tryGrowByReslice(n int) (int, bool) {
	if l := len(b.buf); n <= cap(b.buf)-l {
		b.buf = b.buf[:l+n]
		return l, true
	}
	return 0, false
}

func (b *buffer) grow() int {
	size := cap(b.buf)
	newBuf := make([]byte, size, size*2)
	copy(newBuf[0:size], b.buf[0:size])
	b.buf = newBuf
	// fmt.Printf("%d %d\n", len(b.buf), cap(b.buf))
	return len(b.buf)
}

func (b *buffer) Reset() {
	b.buf = make([]byte, 0, b.originCap)
	b.off = 0
}

func (b *buffer) Bytes() []byte          { return b.buf[:cap(b.buf)] }
func (b *buffer) AvailableBytes() []byte { return b.buf[b.off:] }
func (b *buffer) Len() int               { return len(b.buf) - b.off }
