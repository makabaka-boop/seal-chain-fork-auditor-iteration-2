// Package audit validates and rebuilds hash-chained evidence-seal events.
//
// Events may be uploaded by different workstations in arbitrary order, so all
// checks operate purely on the id/parentId graph and the declared digests;
// the upload order is never trusted.
package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// ZeroDigest is the prevDigest declared by the unique root event:
// 32 zero bytes rendered as 64 lowercase hexadecimal characters.
const ZeroDigest = "0000000000000000000000000000000000000000000000000000000000000000"

// ComputeDigest recomputes one event digest.
//
// The signed byte sequence, concatenated in this exact order, is hashed with
// SHA-256 and rendered as 64 lowercase hex characters:
//
//  1. 4-byte big-endian length of id, followed by the UTF-8 bytes of id;
//  2. the 32 raw bytes of prevDigest (all zero for the root event);
//  3. 4-byte big-endian length of payload, followed by the UTF-8 bytes of
//     payload.
//
// parentId is deliberately not part of the digest: the link is authenticated
// separately by comparing prevDigest against the parent's declared digest.
func ComputeDigest(id, payload string, prevRaw [32]byte) string {
	idBytes := []byte(id)
	payloadBytes := []byte(payload)

	total := 4 + len(idBytes) + 32 + 4 + len(payloadBytes)
	buf := make([]byte, 0, total)

	var lengthPrefix [4]byte
	binary.BigEndian.PutUint32(lengthPrefix[:], uint32(len(idBytes)))
	buf = append(buf, lengthPrefix[:]...)
	buf = append(buf, idBytes...)
	buf = append(buf, prevRaw[:]...)

	binary.BigEndian.PutUint32(lengthPrefix[:], uint32(len(payloadBytes)))
	buf = append(buf, lengthPrefix[:]...)
	buf = append(buf, payloadBytes...)

	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}
