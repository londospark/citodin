package main

import "core:testing"

NCSD_MAGIC_OFFSET :: 0x100
NCSD_FLAGS_OFFSET  :: 0x188
NCSD_PARTITIONS_OFFSET :: 0x120

PartitionEntry :: struct {
	offset_sectors: u32,
	length_sectors: u32,
}

partition_entry_offset_bytes :: proc(e: PartitionEntry, sector_size: u32) -> u64 {
	return u64(e.offset_sectors) * u64(sector_size)
}

partition_entry_length_bytes :: proc(e: PartitionEntry, sector_size: u32) -> u64 {
	return u64(e.length_sectors) * u64(sector_size)
}

partition_entry_is_empty :: proc(e: PartitionEntry) -> bool {
	return e.length_sectors == 0 || e.offset_sectors == 0
}

NcsdHeader :: struct {
	sector_size: u32,
	partitions:  [8]PartitionEntry,
}

ncsd_parse :: proc(data: []byte) -> (NcsdHeader, bool) {
	r := reader_make(data)

	if !reader_seek(&r, NCSD_MAGIC_OFFSET) { return {}, false }
	magic, magic_ok := reader_read_bytes(&r, 4)
	if !magic_ok || string(magic) != "NCSD" { return {}, false }

	if !reader_seek(&r, NCSD_FLAGS_OFFSET) { return {}, false }
	flags, flags_ok := reader_read_bytes(&r, 8)
	if !flags_ok { return {}, false }
	sector_size := u32(0x200) * (1 << u32(flags[6]))

	if !reader_seek(&r, NCSD_PARTITIONS_OFFSET) { return {}, false }
	partitions: [8]PartitionEntry
	for i := 0; i < 8; i += 1 {
		offset, offset_ok := reader_read_u32_le(&r)
		if !offset_ok { return {}, false }
		length, length_ok := reader_read_u32_le(&r)
		if !length_ok { return {}, false }
		partitions[i] = PartitionEntry{
			offset_sectors = offset,
			length_sectors = length,
		}
	}

	return NcsdHeader{sector_size = sector_size, partitions = partitions}, true
}

@(test)
test_parse_valid_ncsd_header :: proc(t: ^testing.T) {
	data := make([]byte, 512)
	defer delete(data)

	copy(data[NCSD_MAGIC_OFFSET:], "NCSD")
	data[NCSD_FLAGS_OFFSET + 6] = 0

	offs_bytes := u32_to_le_bytes(0x1000)
	copy(data[NCSD_PARTITIONS_OFFSET:], offs_bytes[:])
	len_bytes := u32_to_le_bytes(0x2000)
	copy(data[NCSD_PARTITIONS_OFFSET + 4:], len_bytes[:])

	header, ok := ncsd_parse(data)
	testing.expect(t, ok, "ncsd_parse should succeed")
	testing.expect_value(t, header.sector_size, u32(0x200))
	testing.expect_value(t, header.partitions[0].offset_sectors, u32(0x1000))
	testing.expect_value(t, header.partitions[0].length_sectors, u32(0x2000))
}

@(test)
test_reject_invalid_ncsd_magic :: proc(t: ^testing.T) {
	data := make([]byte, 512)
	defer delete(data)

	copy(data[NCSD_MAGIC_OFFSET:], "XXXX")

	_, ok := ncsd_parse(data)
	testing.expect(t, !ok, "invalid magic should be rejected")
}

@(test)
test_ncsd_sector_size_calculation :: proc(t: ^testing.T) {
	data := make([]byte, 512)
	defer delete(data)

	copy(data[NCSD_MAGIC_OFFSET:], "NCSD")
	data[NCSD_FLAGS_OFFSET + 6] = 1

	header, ok := ncsd_parse(data)
	testing.expect(t, ok, "ncsd_parse should succeed")
	testing.expect_value(t, header.sector_size, u32(0x400))
}

@(test)
test_partition_entry_helpers :: proc(t: ^testing.T) {
	e := PartitionEntry{offset_sectors = 0x100, length_sectors = 0x200}
	testing.expect_value(t, partition_entry_offset_bytes(e, 0x200), u64(0x100 * 0x200))
	testing.expect_value(t, partition_entry_length_bytes(e, 0x200), u64(0x200 * 0x200))
	testing.expect(t, !partition_entry_is_empty(e), "non-empty entry")

	empty := PartitionEntry{}
	testing.expect(t, partition_entry_is_empty(empty), "empty entry")
}

u32_to_le_bytes :: proc(val: u32) -> [4]byte {
	bytes: [4]byte
	bytes[0] = byte(val)
	bytes[1] = byte(val >> 8)
	bytes[2] = byte(val >> 16)
	bytes[3] = byte(val >> 24)
	return bytes
}
