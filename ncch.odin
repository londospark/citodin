package main

import "core:testing"

NCCH_KEYY_OFFSET         :: 0x000
NCCH_TITLE_ID_OFFSET     :: 0x108
NCCH_EXHEADER_LEN_OFFSET :: 0x180
NCCH_FLAGS_OFFSET        :: 0x188
NCCH_PLAIN_OFFSET        :: 0x190
NCCH_LOGO_OFFSET         :: 0x198
NCCH_EXEFS_OFFSET        :: 0x1A0
NCCH_RESERVED_SIZE       :: 8
NCCH_ROMFS_OFFSET        :: 0x1B0

NcchHeader :: struct {
	key_y:           u128,
	title_id:        u64,
	partition_flags: [8]u8,
	exheader_length: u32,
	plain_offset:    u32,
	plain_length:    u32,
	logo_offset:     u32,
	logo_length:     u32,
	exefs_offset:    u32,
	exefs_length:    u32,
	romfs_offset:    u32,
	romfs_length:    u32,
}

ncch_parse :: proc(data: []byte, partition_offset: int) -> (NcchHeader, bool) {
	r := reader_make(data)

	if !reader_seek(&r, partition_offset + NCCH_KEYY_OFFSET) { return {}, false }
	key_y, ky_ok := reader_read_u128_be(&r)
	if !ky_ok { return {}, false }

	if !reader_seek(&r, partition_offset + NCCH_TITLE_ID_OFFSET) { return {}, false }
	title_id, ti_ok := reader_read_u64_le(&r)
	if !ti_ok { return {}, false }

	if !reader_seek(&r, partition_offset + NCCH_EXHEADER_LEN_OFFSET) { return {}, false }
	exheader_length, eh_ok := reader_read_u32_le(&r)
	if !eh_ok { return {}, false }

	if !reader_seek(&r, partition_offset + NCCH_FLAGS_OFFSET) { return {}, false }
	flags_slice, fs_ok := reader_read_bytes(&r, 8)
	if !fs_ok { return {}, false }
	partition_flags: [8]u8
	copy(partition_flags[:], flags_slice)

	if !reader_seek(&r, partition_offset + NCCH_PLAIN_OFFSET) { return {}, false }
	plain_offset, po_ok := reader_read_u32_le(&r)
	if !po_ok { return {}, false }
	plain_length, pl_ok := reader_read_u32_le(&r)
	if !pl_ok { return {}, false }

	logo_offset, lo_ok := reader_read_u32_le(&r)
	if !lo_ok { return {}, false }
	logo_length, ll_ok := reader_read_u32_le(&r)
	if !ll_ok { return {}, false }

	exefs_offset, eo_ok := reader_read_u32_le(&r)
	if !eo_ok { return {}, false }
	exefs_length, el_ok := reader_read_u32_le(&r)
	if !el_ok { return {}, false }

	if !reader_skip(&r, NCCH_RESERVED_SIZE) { return {}, false }

	romfs_offset, ro_ok := reader_read_u32_le(&r)
	if !ro_ok { return {}, false }
	romfs_length, rl_ok := reader_read_u32_le(&r)
	if !rl_ok { return {}, false }

	return NcchHeader{
		key_y = key_y,
		title_id = title_id,
		partition_flags = partition_flags,
		exheader_length = exheader_length,
		plain_offset = plain_offset,
		plain_length = plain_length,
		logo_offset = logo_offset,
		logo_length = logo_length,
		exefs_offset = exefs_offset,
		exefs_length = exefs_length,
		romfs_offset = romfs_offset,
		romfs_length = romfs_length,
	}, true
}

ncch_crypto_method :: proc(h: ^NcchHeader) -> (CryptoMethod, bool) {
	return crypto_method_from_flag(h.partition_flags[3])
}

ncch_is_no_crypto :: proc(h: ^NcchHeader) -> bool {
	return h.partition_flags[7] & 0x04 != 0
}

ncch_is_fixed_key :: proc(h: ^NcchHeader) -> bool {
	return h.partition_flags[7] & 0x01 != 0
}

ncch_plain_iv :: proc(h: ^NcchHeader) -> u128 {
	return (u128(h.title_id) << 64) | 0x0100_0000_0000_0000
}

ncch_exefs_iv :: proc(h: ^NcchHeader) -> u128 {
	return (u128(h.title_id) << 64) | 0x0200_0000_0000_0000
}

ncch_romfs_iv :: proc(h: ^NcchHeader) -> u128 {
	return (u128(h.title_id) << 64) | 0x0300_0000_0000_0000
}

create_minimal_ncch_header :: proc() -> []byte {
	data := make([]byte, 0x200)

	key_y := u128(0x12345678_9ABCDEF0_FEDCBA98_76543210)
	be_bytes := u128_to_be_bytes(key_y)
	copy(data[NCCH_KEYY_OFFSET:], be_bytes[:])

	title_id := u64(0x0004000000055D00)
	le_tid := u64_to_le_bytes(title_id)
	copy(data[NCCH_TITLE_ID_OFFSET:], le_tid[:])

	eh := u32_to_le_bytes(0x800)
	copy(data[NCCH_EXHEADER_LEN_OFFSET:], eh[:])

	po := u32_to_le_bytes(0x0000)
	copy(data[NCCH_PLAIN_OFFSET:], po[:])
	pl := u32_to_le_bytes(0x0000)
	copy(data[NCCH_PLAIN_OFFSET + 4:], pl[:])

	lg_o := u32_to_le_bytes(0x0000)
	copy(data[NCCH_LOGO_OFFSET:], lg_o[:])
	lg_l := u32_to_le_bytes(0x0000)
	copy(data[NCCH_LOGO_OFFSET + 4:], lg_l[:])

	eo := u32_to_le_bytes(0x1000)
	copy(data[NCCH_EXEFS_OFFSET:], eo[:])
	el := u32_to_le_bytes(0x0800)
	copy(data[NCCH_EXEFS_OFFSET + 4:], el[:])

	ro := u32_to_le_bytes(0x2000)
	copy(data[NCCH_ROMFS_OFFSET:], ro[:])
	rl := u32_to_le_bytes(0x4000)
	copy(data[NCCH_ROMFS_OFFSET + 4:], rl[:])

	return data
}

u64_to_le_bytes :: proc(val: u64) -> [8]byte {
	bytes: [8]byte
	bytes[0] = byte(val)
	bytes[1] = byte(val >> 8)
	bytes[2] = byte(val >> 16)
	bytes[3] = byte(val >> 24)
	bytes[4] = byte(val >> 32)
	bytes[5] = byte(val >> 40)
	bytes[6] = byte(val >> 48)
	bytes[7] = byte(val >> 56)
	return bytes
}

@(test)
test_parse_ncch_header :: proc(t: ^testing.T) {
	data := create_minimal_ncch_header()
	defer delete(data)

	header, ok := ncch_parse(data, 0)
	testing.expect(t, ok, "ncch_parse should succeed")

	testing.expect_value(t, header.key_y, u128(0x12345678_9ABCDEF0_FEDCBA98_76543210))
	testing.expect_value(t, header.title_id, u64(0x0004000000055D00))
	testing.expect_value(t, header.exheader_length, u32(0x800))
	testing.expect_value(t, header.exefs_offset, u32(0x1000))
	testing.expect_value(t, header.exefs_length, u32(0x800))
	testing.expect_value(t, header.romfs_offset, u32(0x2000))
	testing.expect_value(t, header.romfs_length, u32(0x4000))
}

@(test)
test_ncch_crypto_method_detection :: proc(t: ^testing.T) {
	methods := [?]struct{f: u8, m: CryptoMethod}{
		{f = 0x00, m = .Original},
		{f = 0x01, m = .Key7x},
		{f = 0x0A, m = .Key93},
		{f = 0x0B, m = .Key96},
	}
	for test in methods {
		data := create_minimal_ncch_header()
		data[NCCH_FLAGS_OFFSET + 3] = test.f
		header, h_ok := ncch_parse(data, 0)
		testing.expect(t, h_ok, "ncch_parse should succeed")
		method, m_ok := ncch_crypto_method(&header)
		testing.expect(t, m_ok, "crypto method should be known")
		testing.expect_value(t, method, test.m)
		delete(data)
	}
}

@(test)
test_ncch_no_crypto_flag :: proc(t: ^testing.T) {
	data := create_minimal_ncch_header()
	defer delete(data)

	data[NCCH_FLAGS_OFFSET + 7] = 0x04

	header, ok := ncch_parse(data, 0)
	testing.expect(t, ok, "ncch_parse should succeed")
	testing.expect(t, ncch_is_no_crypto(&header), "NoCrypto should be set")
	testing.expect(t, !ncch_is_fixed_key(&header), "FixedKey should not be set")
}

@(test)
test_ncch_fixed_key_flag :: proc(t: ^testing.T) {
	data := create_minimal_ncch_header()
	defer delete(data)

	data[NCCH_FLAGS_OFFSET + 7] = 0x01

	header, ok := ncch_parse(data, 0)
	testing.expect(t, ok, "ncch_parse should succeed")
	testing.expect(t, ncch_is_fixed_key(&header), "FixedKey should be set")
	testing.expect(t, !ncch_is_no_crypto(&header), "NoCrypto should not be set")
}

@(test)
test_ncch_iv_construction :: proc(t: ^testing.T) {
	data := create_minimal_ncch_header()
	defer delete(data)

	header, ok := ncch_parse(data, 0)
	testing.expect(t, ok, "ncch_parse should succeed")

	title := u128(header.title_id)
	testing.expect_value(t, ncch_plain_iv(&header), (title << 64) | 0x0100_0000_0000_0000)
	testing.expect_value(t, ncch_exefs_iv(&header), (title << 64) | 0x0200_0000_0000_0000)
	testing.expect_value(t, ncch_romfs_iv(&header), (title << 64) | 0x0300_0000_0000_0000)
}
