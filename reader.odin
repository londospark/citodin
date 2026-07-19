package main

import "core:encoding/endian"
import "core:testing"

Reader :: struct {
	data:   []byte,
	offset: int,
}

reader_make :: proc(data: []byte) -> Reader {
	return Reader{data = data, offset = 0}
}

reader_remaining :: proc(r: ^Reader) -> int {
	return len(r.data) - r.offset
}

reader_tell :: proc(r: ^Reader) -> int {
	return r.offset
}

reader_seek :: proc(r: ^Reader, pos: int) -> bool {
	if pos < 0 || pos > len(r.data) { return false }
	r.offset = pos
	return true
}

reader_skip :: proc(r: ^Reader, n: int) -> bool {
	return reader_seek(r, r.offset + n)
}

reader_peek :: proc(r: ^Reader) -> (byte, bool) {
	if r.offset >= len(r.data) { return 0, false }
	return r.data[r.offset], true
}

reader_read_u8 :: proc(r: ^Reader) -> (u8, bool) {
	if r.offset + 1 > len(r.data) { return 0, false }
	val := r.data[r.offset]
	r.offset += 1
	return val, true
}

reader_read_u16_le :: proc(r: ^Reader) -> (u16, bool) {
	if r.offset + 2 > len(r.data) { return 0, false }
	val := endian.unchecked_get_u16le(r.data[r.offset:])
	r.offset += 2
	return val, true
}

reader_read_u32_le :: proc(r: ^Reader) -> (u32, bool) {
	if r.offset + 4 > len(r.data) { return 0, false }
	val := endian.unchecked_get_u32le(r.data[r.offset:])
	r.offset += 4
	return val, true
}

reader_read_u64_le :: proc(r: ^Reader) -> (u64, bool) {
	if r.offset + 8 > len(r.data) { return 0, false }
	val := endian.unchecked_get_u64le(r.data[r.offset:])
	r.offset += 8
	return val, true
}

reader_read_u128_be :: proc(r: ^Reader) -> (u128, bool) {
	if r.offset + 16 > len(r.data) { return 0, false }
	hi := u128(endian.unchecked_get_u64be(r.data[r.offset:]))
	lo := u128(endian.unchecked_get_u64be(r.data[r.offset + 8:]))
	r.offset += 16
	return (hi << 64) | lo, true
}

reader_read_bytes :: proc(r: ^Reader, n: int) -> ([]byte, bool) {
	if r.offset + n > len(r.data) { return nil, false }
	slice := r.data[r.offset:r.offset + n]
	r.offset += n
	return slice, true
}

reader_read_exact :: proc(r: ^Reader, dst: []byte) -> bool {
	if r.offset + len(dst) > len(r.data) { return false }
	copy(dst, r.data[r.offset:])
	r.offset += len(dst)
	return true
}

@(test)
test_reader_read_in_bounds :: proc(t: ^testing.T) {
	data := []byte{
		0x01,                                           // u8 = 1
		0x34, 0x12,                                     // u16 LE = 0x1234
		0x78, 0x56, 0x34, 0x12,                         // u32 LE = 0x12345678
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // u128 BE = 0x01234567_89ABCDEF...
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // ...continued
	}
	r := reader_make(data)

	testing.expect_value(t, reader_tell(&r), 0)

	val_u8, u8_ok := reader_read_u8(&r)
	testing.expect(t, u8_ok, "read_u8")
	testing.expect_value(t, val_u8, u8(0x01))

	val_u16, u16_ok := reader_read_u16_le(&r)
	testing.expect(t, u16_ok, "read_u16_le")
	testing.expect_value(t, val_u16, u16(0x1234))

	val_u32, u32_ok := reader_read_u32_le(&r)
	testing.expect(t, u32_ok, "read_u32_le")
	testing.expect_value(t, val_u32, u32(0x12345678))

	val_u128, u128_ok := reader_read_u128_be(&r)
	testing.expect(t, u128_ok, "read_u128_be")
	testing.expect_value(t, val_u128, u128(0x0123456789ABCDEF0123456789ABCDEF))

	testing.expect_value(t, reader_remaining(&r), 0)
}

@(test)
test_reader_out_of_bounds :: proc(t: ^testing.T) {
	data := []byte{0x01, 0x02}
	r := reader_make(data)

	_, ok32 := reader_read_u32_le(&r)
	testing.expect(t, !ok32, "read_u32_le should fail with 2 bytes")

	_, ok128 := reader_read_u128_be(&r)
	testing.expect(t, !ok128, "read_u128_be should fail with 2 bytes")

	_, ok_bytes := reader_read_bytes(&r, 3)
	testing.expect(t, !ok_bytes, "read_bytes(3) should fail with 2 bytes")

	val_first, ok_r1 := reader_read_u8(&r)
	testing.expect(t, ok_r1, "read_u8 should succeed")
	testing.expect_value(t, val_first, u8(0x01))

	val_second, ok_r2 := reader_read_u8(&r)
	testing.expect(t, ok_r2, "read_u8 should succeed")
	testing.expect_value(t, val_second, u8(0x02))

	_, ok_end := reader_read_u8(&r)
	testing.expect(t, !ok_end, "read_u8 should fail at end")
}

@(test)
test_reader_seek_and_skip :: proc(t: ^testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	r := reader_make(data)

	ok := reader_skip(&r, 2)
	testing.expect(t, ok, "skip 2")
	testing.expect_value(t, reader_tell(&r), 2)

	ok = reader_seek(&r, 0)
	testing.expect(t, ok, "seek to 0")

	u8val, _ := reader_read_u8(&r)
	testing.expect_value(t, u8val, u8(0x01))

	ok = reader_skip(&r, 10)
	testing.expect(t, !ok, "skip beyond end should fail")
}

@(test)
test_reader_read_exact :: proc(t: ^testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	r := reader_make(data)

	dst := make([]byte, 3)
	ok := reader_read_exact(&r, dst)
	testing.expect(t, ok, "read_exact 3 bytes")
	testing.expect_value(t, dst[0], byte(0x01))
	testing.expect_value(t, dst[1], byte(0x02))
	testing.expect_value(t, dst[2], byte(0x03))

	dst2 := make([]byte, 5)
	ok = reader_read_exact(&r, dst2)
	testing.expect(t, !ok, "read_exact 5 should fail with 2 remaining")
}
