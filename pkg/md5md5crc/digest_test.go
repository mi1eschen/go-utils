package md5md5crc_test

import (
	"encoding/hex"
	"io"
	"os"
	"testing"

	"github.com/mi1eschen/go-utils/pkg/md5md5crc"
)

const answer = "6e54ac6aefab46e765686eb309142474"

func TestDigest(t *testing.T) {
	path := `testdata\testdata.csv`

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open file: %s", err)
	}
	defer f.Close()

	digest := md5md5crc.NewDigestWithType(512, 33554432/512, md5md5crc.TypeCRC32C)
	io.Copy(digest, f)

	actual := digest.Sum(nil)
	if hex.EncodeToString(actual) != answer {
		t.Fatalf("want %s but got %s", answer, hex.EncodeToString(actual))
	}
	f.Close()
}
