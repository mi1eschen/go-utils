package md5md5crc

import (
	"encoding/binary"
	"fmt"
	"hash"
	"hash/crc32"
)

type ChecksumType int8

const (
	TypeCRC32  ChecksumType = 0
	TypeCRC32C ChecksumType = 1
)

type dataChecksum struct {
	id               int
	size             int
	summer           hash.Hash32
	bytesPerChecksum int
	inSum            int
}

func NewCrc32DataChecksum(chunkSize int) *dataChecksum {
	return &dataChecksum{
		id:   1,
		size: 4,

		bytesPerChecksum: chunkSize,
		summer:           crc32.NewIEEE(),
	}
}

func NewDataChecksum(chunkSize int, checksumType ChecksumType) *dataChecksum {
	var summer hash.Hash32
	switch checksumType {
	case TypeCRC32C:
		summer = crc32.New(crc32.MakeTable(crc32.Castagnoli))
	case TypeCRC32:
		summer = crc32.NewIEEE()
	default:
		summer = crc32.NewIEEE()
	}

	return &dataChecksum{
		id:   1,
		size: 4,

		bytesPerChecksum: chunkSize,
		summer:           summer,
	}
}

func (c *dataChecksum) update(p []byte) (int, error) {
	n, err := c.summer.Write(p)
	if err != nil {
		return 0, err
	}
	c.inSum += n
	return n, err
}

func (c *dataChecksum) writeByteValue(p []byte, offset int, reset bool) (int, error) {
	if c.size <= 0 {
		return 0, nil
	}

	if c.size == 4 {
		val := c.summer.Sum32()
		binary.BigEndian.PutUint32(p, val)
	} else {
		return 0, fmt.Errorf("unknown checksumType: %v", c.size)
	}

	if reset {
		c.reset()
	}
	return c.size, nil
}

func (c *dataChecksum) reset() {
	c.summer.Reset()
	c.inSum = 0
}
