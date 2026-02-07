package protocol

import "hash/crc32"

var crcTable = crc32.MakeTable(crc32.IEEE)

// Checksum computes CRC32 (IEEE) over the given data.
func Checksum(data []byte) uint32 {
	return crc32.Checksum(data, crcTable)
}
