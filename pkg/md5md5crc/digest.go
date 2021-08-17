package md5md5crc

import (
	"bytes"
	"crypto/md5"
	"hash"
)

var _ hash.Hash = (*md5md5crcMessageDigest)(nil)

type md5md5crcMessageDigest struct {
	bytesPerCrc  int
	crcsPerBlock int
	crcCount     int
	bytesRead    int

	crc []byte

	md5Digest hash.Hash
	checksum  *dataChecksum

	blockChecksumBuffer bytes.Buffer
	md5DigestBuffer     *buffer
}

func NewDigest(bytesPerCrc int, crcsPerBlock int) *md5md5crcMessageDigest {
	return NewDigestWithType(bytesPerCrc, crcsPerBlock, TypeCRC32)
}

func NewDigestWithType(bytesPerCrc int, crcsPerBlock int, checksumType ChecksumType) *md5md5crcMessageDigest {
	return &md5md5crcMessageDigest{
		bytesPerCrc:  bytesPerCrc,
		crcsPerBlock: crcsPerBlock,
		crc:          make([]byte, 4),

		md5Digest: md5.New(),
		checksum:  NewDataChecksum(bytesPerCrc, checksumType),

		// blockChecksumBuffer: newBuffer(32),
		md5DigestBuffer: newBuffer(32),
	}
}

func (d *md5md5crcMessageDigest) Write(p []byte) (int, error) {
	bytesRemaining := len(p)
	bytesToComplete := d.bytesPerCrc - d.bytesRead
	i := 0

	if bytesRemaining >= bytesToComplete {
		if n, err := d.checksum.update(p[i:bytesToComplete]); err != nil {
			return n, err
		}
		bytesRemaining -= bytesToComplete
		i += bytesToComplete
		if err := d.flushCrcToBuffer(); err != nil {
			return 0, err
		}
	}

	for bytesRemaining >= d.bytesPerCrc {
		if n, err := d.checksum.update(p[i : i+d.bytesPerCrc]); err != nil {
			return n, err
		}
		bytesRemaining -= d.bytesPerCrc
		i += d.bytesPerCrc
		if err := d.flushCrcToBuffer(); err != nil {
			return 0, err
		}
	}

	if bytesRemaining > 0 {
		if n, err := d.checksum.update(p[i : i+bytesRemaining]); err != nil {
			return n, err
		}
		d.bytesRead += bytesRemaining
	}

	return len(p), nil
}

func (d *md5md5crcMessageDigest) flushCrcToBuffer() error {
	crcLen, err := d.checksum.writeByteValue(d.crc, 0, true)
	if err != nil {
		return err
	}

	if _, err := d.blockChecksumBuffer.Write(d.crc[:crcLen]); err != nil {
		return err
	}

	d.bytesRead = 0
	d.crcCount += 1

	if d.crcCount == d.crcsPerBlock {
		if err := d.calculateMD5OfBlockCrcs(); err != nil {
			return err
		}
	}
	return nil
}

func (d *md5md5crcMessageDigest) calculateMD5OfBlockCrcs() error {
	// if _, err := d.md5Digest.Write(d.blockChecksumBuffer.AvailableBytes()); err != nil {
	if _, err := d.md5Digest.Write(d.blockChecksumBuffer.Bytes()); err != nil {
		return err
	}

	val := d.md5Digest.Sum(nil)
	if _, err := d.md5DigestBuffer.Write(val); err != nil {
		return err
	}
	d.blockChecksumBuffer.Reset()
	d.md5Digest.Reset()
	d.crcCount = 0
	return nil
}

func (d *md5md5crcMessageDigest) Sum(b []byte) []byte {
	if d.bytesRead > 0 {
		if err := d.flushCrcToBuffer(); err != nil {
			return nil
		}
	}

	if d.blockChecksumBuffer.Len() > 0 {
		if err := d.calculateMD5OfBlockCrcs(); err != nil {
			return nil
		}
	}

	d.md5Digest.Write(d.md5DigestBuffer.Bytes())
	return d.md5Digest.Sum(nil)
}

func (d *md5md5crcMessageDigest) Reset() {
	d.blockChecksumBuffer.Reset()
	d.md5DigestBuffer = newBuffer(32)

	d.checksum.reset()
	d.md5Digest.Reset()

	d.bytesRead = 0
	d.crcCount = 0
}

func (d *md5md5crcMessageDigest) Size() int {
	return 16
}

func (d *md5md5crcMessageDigest) BlockSize() int {
	return 64
}
