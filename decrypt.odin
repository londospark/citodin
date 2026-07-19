package main

import "core:encoding/endian"
import "core:fmt"
import "core:os"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:bytes"
import vmem "core:mem/virtual"

CHUNK_SIZE :: 4 * 1024 * 1024

Not_Ncsd :: struct {}
Key_Not_Found :: struct { name: string }

Decrypt_Error :: union {
	Not_Ncsd,
	Key_Not_Found,
	vmem.Map_File_Error,
}

Chunk_Work :: struct {
	key:        [16]u8,
	key_second: Maybe([16]u8),
	base_iv:    u128,
	data:       []byte,
	wg:         ^sync.Wait_Group,
}

is_content_decrypted :: proc(data: []byte, h: ^NcchHeader, sector_size: u32, part_offset: int) -> bool {
	ss := int(sector_size)
	if h.exefs_length > 0 {
		exefs_base := part_offset + int(h.exefs_offset) * ss
		if exefs_base + 8 <= len(data) {
			all_ascii := true
			for b in data[exefs_base:exefs_base + 8] {
				if b != 0x00 && (b < 0x20 || b > 0x7E) {
					all_ascii = false
					break
				}
			}
			if all_ascii { return true }
		}
	}
	if h.exheader_length > 0 {
		exheader_off := part_offset + ss
		if exheader_off + 8 <= len(data) {
			all_ascii := true
			for b in data[exheader_off:exheader_off + 8] {
				if b != 0x00 && (b < 0x20 || b > 0x7E) {
					all_ascii = false
					break
				}
			}
			if all_ascii { return true }
		}
	}
	return false
}

decrypt_slice :: proc(data: []byte, key: ^[16]u8, key_second: Maybe([16]u8), base_iv: u128, chunk_size: int) {
	total_len := len(data)
	if total_len == 0 { return }

	num_chunks := (total_len + chunk_size - 1) / chunk_size
	if num_chunks > 8 { num_chunks = 8 }
	actual_chunk := (total_len + num_chunks - 1) / num_chunks
	if actual_chunk < 1024 { actual_chunk = total_len }

	if num_chunks <= 1 {
		blocks_before: u128 = 0
		chunk_iv := base_iv + blocks_before
		aes_ctr_decrypt(key, chunk_iv, data)
		if ks, ok := key_second.?; ok {
			aes_ctr_decrypt(&ks, chunk_iv, data)
		}
		return
	}

	wg: sync.Wait_Group
	sync.wait_group_add(&wg, num_chunks)

	for i := 0; i < num_chunks; i += 1 {
		start := i * actual_chunk
		end := min(start + actual_chunk, total_len)
		chunk_data := data[start:end]
		blocks_before := u128(start) / 16
		chunk_iv := base_iv + blocks_before

		work := new(Chunk_Work)
		work.key = key^
		work.key_second = key_second
		work.base_iv = chunk_iv
		work.data = chunk_data
		work.wg = &wg

		thread.run_with_data(work, proc(work_ptr: rawptr) {
			w := (^Chunk_Work)(work_ptr)
			aes_ctr_decrypt(&w.key, w.base_iv, w.data)
			if ks, ok := w.key_second.?; ok {
				aes_ctr_decrypt(&ks, w.base_iv, w.data)
			}
			sync.wait_group_done(w.wg)
			free(w)
		})
	}

	sync.wait_group_wait(&wg)
}

resolve_key_x :: proc(method: CryptoMethod, db: ^KeyDatabase) -> (u128, bool) {
	slot := resolve_slot(method)
	return keydb_get_key_x(db, u8(slot))
}

decrypt_rom :: proc(path: string, db: ^KeyDatabase, progress: proc(string, rawptr), user_data: rawptr = nil) -> Decrypt_Error {
	progress(fmt.tprintf("Using external key database (%d keys loaded)", keydb_len(db)), user_data)

	data, map_err := vmem.map_file_from_path(path, {.Read, .Write})
	if map_err != nil {
		return map_err
	}
	defer vmem.unmap_file(data)

	ncsd, ncsd_ok := ncsd_parse(data)
	if !ncsd_ok {
		return Not_Ncsd{}
	}
	sector_size := ncsd.sector_size
	ss := int(sector_size)

	for p := u8(0); p < 8; p += 1 {
		part := ncsd.partitions[p]
		if partition_entry_is_empty(part) {
			progress(fmt.tprintf("Partition %d Not found... Skipping...", p), user_data)
			continue
		}

		part_off := int(partition_entry_offset_bytes(part, sector_size))
		if part_off + 0x104 > len(data) { continue }

		if string(data[part_off + 0x100:part_off + 0x104]) != "NCCH" {
			progress(fmt.tprintf("Partition %d Unable to read NCCH header", p), user_data)
			continue
		}

		ncch_initial, ncch_ok := ncch_parse(data, part_off)
		if !ncch_ok { continue }

		use_ncch := ncch_initial

		if ncch_is_no_crypto(&use_ncch) {
			if is_content_decrypted(data, &use_ncch, sector_size, part_off) {
				progress(fmt.tprintf("Partition %d: Already Decrypted ✓", p), user_data)
				continue
			}
			progress(fmt.tprintf("Partition %d: Flagged as decrypted but content is encrypted, decrypting...", p), user_data)

			data[part_off + 0x18F] &= ~u8(0x04)
			backup_offset := 0x1188 + int(p) * 8 + 3
			if backup_offset < len(data) {
				backup_crypto := data[backup_offset]
				if backup_crypto != 0 {
					if _, valid := crypto_method_from_flag(backup_crypto); valid {
						data[part_off + 0x18B] = backup_crypto
					}
				}
			}

			reparsed, re_ok := ncch_parse(data, part_off)
			if !re_ok { continue }
			use_ncch = reparsed
		}

		if is_content_decrypted(data, &use_ncch, sector_size, part_off) {
			progress(fmt.tprintf("Partition %d: Content already decrypted (mis-flagged ROM), setting NoCrypto flag...", p), user_data)

			data[part_off + 0x18B] = 0x00
			flag := use_ncch.partition_flags[7]
			flag &= ~u8(0x01)
			flag &= ~u8(0x20)
			flag |= 0x04
			data[part_off + 0x18F] = flag
			continue
		}

		key_y := use_ncch.key_y
		normal_key_2c, normal_key: u128
		if ncch_is_fixed_key(&use_ncch) {
			if p == 0 { progress("Encryption Method: Zero Key", user_data) }
			normal_key_2c = 0
			normal_key = 0
		} else {
			constant, const_ok := keydb_generator(db)
			if !const_ok { return Key_Not_Found{"generator"} }
			key_x_2c, kx2c_ok := keydb_get_key_x(db, 0x2C)
			if !kx2c_ok { return Key_Not_Found{"slot0x2CKeyX"} }
			nk2c := derive_normal_key(key_x_2c, key_y, constant)

			method, method_ok := ncch_crypto_method(&use_ncch)
			if !method_ok { method = .Original }

			key_x, kx_ok := resolve_key_x(method, db)
			if !kx_ok { return Key_Not_Found{fmt.tprintf("slot0x%02XKeyX", resolve_slot(method))} }
			nk := derive_normal_key(key_x, key_y, constant)

			if p == 0 { progress(fmt.tprintf("Encryption Method: %v", method), user_data) }
			normal_key_2c = nk2c
			normal_key = nk
		}

		key_2c := u128_to_be_bytes(normal_key_2c)
		key_main := u128_to_be_bytes(normal_key)

		if use_ncch.exheader_length > 0 {
			off := (int(part.offset_sectors) + 1) * ss
			aes_ctr_decrypt(&key_2c, ncch_plain_iv(&use_ncch), data[off:off + 0x800])
			progress(fmt.tprintf("Partition %d ExeFS: Decrypting: ExHeader", p), user_data)
		}

		if use_ncch.exefs_length > 0 {
			exefs_base := (int(part.offset_sectors) + int(use_ncch.exefs_offset)) * ss
			exefs_iv := ncch_exefs_iv(&use_ncch)

			aes_ctr_decrypt(&key_2c, exefs_iv, data[exefs_base:exefs_base + ss])
			progress(fmt.tprintf("Partition %d ExeFS: Decrypting: ExeFS Filename Table", p), user_data)

			method, method_ok := ncch_crypto_method(&use_ncch)
			if method_ok && (method == .Key7x || method == .Key93 || method == .Key96) {
				for j := u32(0); j < 10; j += 1 {
					slot := exefs_base + int(j) * 0x10
					if slot + 0x10 > exefs_base + ss { break }
					if string(data[slot:slot + 8]) == ".code\x00\x00\x00" {
						code_file_off := endian.unchecked_get_u32le(data[slot + 8:slot + 12])
						code_file_len := int(endian.unchecked_get_u32le(data[slot + 12:slot + 16]))

						if code_file_len > 0 {
							ctr_offset := u128(code_file_off) + u128(ss) / 0x10
							code_iv := exefs_iv + ctr_offset
							code_start := exefs_base + ss + int(code_file_off)

							progress(fmt.tprintf("Partition %d ExeFS: Decrypting: .code (%d mb)", p, code_file_len / (1024 * 1024)), user_data)
							decrypt_slice(data[code_start:code_start + code_file_len], &key_main, key_main, code_iv, 1024 * 1024)
							progress(fmt.tprintf("Partition %d ExeFS: Decrypting: .code... Done!", p), user_data)
						}
						break
					}
				}
			}

			exefs_data_sectors := max(int(use_ncch.exefs_length) - 1, 0)
			if exefs_data_sectors > 0 {
				data_size := exefs_data_sectors * ss
				data_iv := exefs_iv + u128(ss) / 0x10
				data_start := exefs_base + ss

				progress(fmt.tprintf("Partition %d ExeFS: Decrypting: data", p), user_data)
				decrypt_slice(data[data_start:data_start + data_size], &key_2c, nil, data_iv, 1024 * 1024)
				progress(fmt.tprintf("Partition %d ExeFS: Decrypting: Done", p), user_data)
			}
		} else {
			progress(fmt.tprintf("Partition %d ExeFS: No Data... Skipping...", p), user_data)
		}

		if use_ncch.romfs_offset != 0 {
			romfs_total := int(use_ncch.romfs_length) * ss
			romfs_iv := ncch_romfs_iv(&use_ncch)
			romfs_start := (int(part.offset_sectors) + int(use_ncch.romfs_offset)) * ss

			progress(fmt.tprintf("Partition %d RomFS: Decrypting: %d mb", p, romfs_total / (1024 * 1024)), user_data)
			decrypt_slice(data[romfs_start:romfs_start + romfs_total], &key_main, nil, romfs_iv, CHUNK_SIZE)
			progress(fmt.tprintf("Partition %d RomFS: Decrypting: Done", p), user_data)
		} else {
			progress(fmt.tprintf("Partition %d RomFS: No Data... Skipping...", p), user_data)
		}

		data[part_off + 0x18B] = 0x00
		flag := use_ncch.partition_flags[7]
		flag &= ~u8(0x01)
		flag &= ~u8(0x20)
		flag |= 0x04
		data[part_off + 0x18F] = flag
	}

	progress("Done...", user_data)
	return nil
}

resolve_slot :: proc(method: CryptoMethod) -> u32 {
	switch method {
	case .Original: return 0x2C
	case .Key7x:    return 0x25
	case .Key93:    return 0x18
	case .Key96:    return 0x1B
	}
	return 0x2C
}

make_test_ncch :: proc(exefs_offset: u32, exefs_length: u32) -> NcchHeader {
	return NcchHeader{
		title_id     = 0x0004000000055D00,
		exefs_offset = exefs_offset,
		exefs_length = exefs_length,
	}
}

build_exefs_data :: proc(part_offset: int, sector_size: u32, exefs_offset_sectors: u32, first_entry: ^[8]byte) -> []byte {
	exefs_base := part_offset + int(exefs_offset_sectors) * int(sector_size)
	total_size := exefs_base + int(sector_size)
	data := make([]byte, total_size)
	copy(data[exefs_base:], first_entry[:])
	return data
}

@(test)
test_is_content_decrypted_with_plaintext_exefs :: proc(t: ^testing.T) {
	sector_size := u32(0x200)
	part_offset := 0
	exefs_off := u32(4)
	ncch := make_test_ncch(exefs_off, 2)

	entry := [8]byte{'.', 'c', 'o', 'd', 'e', 0, 0, 0}
	data := build_exefs_data(part_offset, sector_size, exefs_off, &entry)
	defer delete(data)

	testing.expect(t, is_content_decrypted(data, &ncch, sector_size, part_offset), "plaintext ExeFS should be detected as decrypted")
}

@(test)
test_is_content_decrypted_with_encrypted_exefs :: proc(t: ^testing.T) {
	sector_size := u32(0x200)
	part_offset := 0
	exefs_off := u32(4)
	ncch := make_test_ncch(exefs_off, 2)

	entry := [8]byte{0xFF, 0xA3, 0x7B, 0x92, 0xDE, 0x01, 0xC4, 0x88}
	data := build_exefs_data(part_offset, sector_size, exefs_off, &entry)
	defer delete(data)

	testing.expect(t, !is_content_decrypted(data, &ncch, sector_size, part_offset), "encrypted ExeFS should not be detected as decrypted")
}

@(test)
test_is_content_decrypted_no_exefs :: proc(t: ^testing.T) {
	sector_size := u32(0x200)
	part_offset := 0
	ncch := make_test_ncch(0, 0)

	data := make([]byte, 0x1000)
	defer delete(data)

	testing.expect(t, !is_content_decrypted(data, &ncch, sector_size, part_offset), "no ExeFS should return false")
}

@(test)
test_is_content_decrypted_with_known_names :: proc(t: ^testing.T) {
	sector_size := u32(0x200)
	part_offset := 0
	exefs_off := u32(4)
	ncch := make_test_ncch(exefs_off, 2)

	known_names := [3][8]byte{
		{'b', 'a', 'n', 'n', 'e', 'r', 0, 0},
		{'i', 'c', 'o', 'n', 0, 0, 0, 0},
		{'l', 'o', 'g', 'o', 0, 0, 0, 0},
	}
	for &name in known_names {
		data := build_exefs_data(part_offset, sector_size, exefs_off, &name)
		testing.expect(t, is_content_decrypted(data, &ncch, sector_size, part_offset), fmt.tprintf("name %s should be detected", string(name[:])))
		delete(data)
	}
}

make_test_keydb :: proc() -> KeyDatabase {
	input := "generator=FEDCBA9876543210FEDCBA9876543210\nslot0x2CKeyX=00000000000000000000000000000001\n"
	db, _ := keydb_from_reader(input)
	return db
}

@(test)
test_decrypt_rom_skips_already_decrypted :: proc(t: ^testing.T) {
	sector_size := u32(0x200)
	ss := int(sector_size)
	part_sector := u32(1)
	part_offset := int(part_sector) * ss
	exefs_off_sectors := u32(4)
	exefs_len_sectors := u32(2)

	total_size := part_offset + (int(exefs_off_sectors) + int(exefs_len_sectors)) * ss
	rom := make([]byte, total_size)
	defer delete(rom)

	copy(rom[0x100:], "NCSD")
	rom[0x18E] = 0
	part_len := exefs_off_sectors + exefs_len_sectors + 1
	obs := u32_to_le_bytes(part_sector)
	copy(rom[0x120:], obs[:])
	pls := u32_to_le_bytes(part_len)
	copy(rom[0x124:], pls[:])

	copy(rom[part_offset + 0x100:], "NCCH")
	tid := u64_to_le_bytes(0x0004000000055D00)
	copy(rom[part_offset + 0x108:], tid[:])
	eh := u32_to_le_bytes(0)
	copy(rom[part_offset + 0x180:], eh[:])
	rom[part_offset + 0x18B] = 0x00
	rom[part_offset + 0x18F] = 0x01
	eo := u32_to_le_bytes(exefs_off_sectors)
	copy(rom[part_offset + 0x1A0:], eo[:])
	el := u32_to_le_bytes(exefs_len_sectors)
	copy(rom[part_offset + 0x1A4:], el[:])
	ro := u32_to_le_bytes(0)
	copy(rom[part_offset + 0x1B0:], ro[:])
	rl := u32_to_le_bytes(0)
	copy(rom[part_offset + 0x1B4:], rl[:])

	exefs_base := part_offset + int(exefs_off_sectors) * ss
	code_entry := [8]byte{'.', 'c', 'o', 'd', 'e', 0, 0, 0}
	copy(rom[exefs_base:], code_entry[:])

	tmp_path := "/tmp/test_content_detect.3ds"
	os.remove(tmp_path)
	if err := os.write_entire_file(tmp_path, rom); err != nil {
		testing.expect(t, false, fmt.tprintf("write temp file: %v", err))
		return
	}
	defer os.remove(tmp_path)

	db := make_test_keydb()
	messages := make([dynamic]string, context.temp_allocator)
	result := decrypt_rom(tmp_path, &db, proc(msg: string, data: rawptr) {
		msgs := (^[dynamic]string)(data)
		append(msgs, msg)
	}, &messages)

	testing.expect(t, result == nil, fmt.tprintf("decrypt_rom should succeed: %v", result))

	output, _ := os.read_entire_file(tmp_path, context.temp_allocator)

	testing.expect(t, bytes.equal(output[exefs_base:exefs_base + 8], code_entry[:]),
		"ExeFS filename should be untouched")

	data_start := exefs_base + ss
	all_zero := true
	for b in output[data_start:data_start + ss] {
		if b != 0 { all_zero = false; break }
	}
	testing.expect(t, all_zero, "ExeFS data sectors should still be zeros")

	testing.expect(t, output[part_offset + 0x18F] & 0x04 == 0x04,
		"NoCrypto flag should be set after content detection")
}
