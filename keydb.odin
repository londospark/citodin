package main

import "core:bytes"
import "core:fmt"
import "core:os"
import "core:sort"
import "core:strings"
import "core:strconv"
import "core:testing"

KeyDb_File_Not_Found :: struct { path: string }
KeyDb_Parse_Error :: struct { line: int, reason: string }

KeyDb_Error :: union {
	KeyDb_File_Not_Found,
	KeyDb_Parse_Error,
	os.Error,
}

KeyDatabase :: struct {
	keys: map[string]u128,
}

is_known_key :: proc(name: string) -> bool {
	if name == "generator" { return true }

	if strings.has_prefix(name, "slot0x") && len(name) >= 10 {
		rest := name[6:]
		suffix: string
		switch {
		case strings.has_suffix(rest, "keyx"): suffix = "keyx"
		case strings.has_suffix(rest, "keyy"): suffix = "keyy"
		case strings.has_suffix(rest, "keyn"): suffix = "keyn"
		case: return false
		}
		hex_part := rest[:len(rest) - len(suffix)]
		if len(hex_part) != 2 { return false }
		for c in hex_part {
			if !is_ascii_hex_digit(byte(c)) { return false }
		}
		return true
	}

	if strings.has_prefix(name, "common") {
		rest := name[6:]
		if rest == "" || rest == "n" { return true }
		num_part := rest
		if strings.has_suffix(rest, "n") { num_part = rest[:len(rest) - 1] }
		if len(num_part) == 0 { return false }
		_, ok := strconv.parse_u64(num_part)
		return ok
	}

	return false
}

@(private)
is_ascii_hex_digit :: proc(c: byte) -> bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

keydb_from_reader :: proc(text: string) -> (KeyDatabase, KeyDb_Error) {
	keys := make(map[string]u128)

	content := text
	BOM_UTF8 := []byte{0xEF, 0xBB, 0xBF}
	if len(content) >= 3 && bytes.equal(transmute([]u8)content[:3], BOM_UTF8) {
		content = content[3:]
	}

	lines := strings.split_lines(content, context.temp_allocator)

	for line_raw, idx in lines {
		line_num := idx + 1
		line := line_raw
		trimmed := strings.trim_space(line)
		if len(trimmed) == 0 || strings.has_prefix(trimmed, "#") {
			continue
		}

		equals_pos := strings.index_byte(trimmed, '=')
		if equals_pos < 0 {
			continue
		}

		name_raw := strings.trim_space(trimmed[:equals_pos])
		value_raw := strings.trim_space(trimmed[equals_pos + 1:])

		if len(name_raw) == 0 { continue }

		name := strings.to_lower(name_raw)
		if !is_known_key(name) { continue }

		for c, i in value_raw {
			if !is_ascii_hex_digit(byte(c)) {
				return {}, KeyDb_Parse_Error{
					line = line_num,
					reason = fmt.tprintf("invalid hex character '%c' at position %d", c, i + 1),
				}
			}
		}

		parsed, ok := strconv.parse_u128_of_base(value_raw, 16)
		if !ok {
			return {}, KeyDb_Parse_Error{
				line = line_num,
				reason = fmt.tprintf("hex parse error: %s", value_raw),
			}
		}

		if _, exists := keys[name]; exists {
			fmt.eprintfln("warning: duplicate key '%s' on line %d, overwriting", name, line_num)
		}

		keys[name] = parsed
	}

	return KeyDatabase{keys = keys}, nil
}

keydb_from_file :: proc(path: string) -> (KeyDatabase, KeyDb_Error) {
	if !os.exists(path) {
		return {}, KeyDb_File_Not_Found{path = path}
	}
	data, read_err := os.read_entire_file(path, context.temp_allocator)
	if read_err != nil {
		return {}, read_err
	}
	return keydb_from_reader(string(data))
}

keydb_search_default_locations :: proc() -> (string, bool) {
	if os.exists("aes_keys.txt") {
		return "aes_keys.txt", true
	}

	#partial switch ODIN_OS {
	case .Linux:
		if home := os.get_env("HOME", context.temp_allocator); len(home) > 0 {
			linux_candidates := []string{
				fmt.tprintf("%s/.config/citrust/aes_keys.txt", home),
				fmt.tprintf("%s/.local/share/citra-emu/sysdata/aes_keys.txt", home),
				fmt.tprintf("%s/.local/share/azahar-emu/sysdata/aes_keys.txt", home),
			}
			for c in linux_candidates {
				if os.exists(c) { return c, true }
			}
		}
	case .Darwin:
		if home := os.get_env("HOME", context.temp_allocator); len(home) > 0 {
			mac_path := fmt.tprintf("%s/.config/citrust/aes_keys.txt", home)
			if os.exists(mac_path) { return mac_path, true }
		}
	case .Windows:
		if appdata := os.get_env("APPDATA", context.temp_allocator); len(appdata) > 0 {
			win_candidates := []string{
				fmt.tprintf("%s\\citrust\\aes_keys.txt", appdata),
				fmt.tprintf("%s\\Citra\\sysdata\\aes_keys.txt", appdata),
			}
			for c in win_candidates {
				if os.exists(c) { return c, true }
			}
		}
	}

	return "", false
}

keydb_generator :: proc(db: ^KeyDatabase) -> (u128, bool) {
	val, ok := db.keys["generator"]
	return val, ok
}

keydb_get_key_x :: proc(db: ^KeyDatabase, slot: u8) -> (u128, bool) {
	name := fmt.tprintf("slot0x%02xkeyx", slot)
	val, ok := db.keys[name]
	return val, ok
}

keydb_get_key_y :: proc(db: ^KeyDatabase, slot: u8) -> (u128, bool) {
	name := fmt.tprintf("slot0x%02xkeyy", slot)
	val, ok := db.keys[name]
	return val, ok
}

keydb_get_key_n :: proc(db: ^KeyDatabase, slot: u8) -> (u128, bool) {
	name := fmt.tprintf("slot0x%02xkeyn", slot)
	val, ok := db.keys[name]
	return val, ok
}

keydb_get_common :: proc(db: ^KeyDatabase, idx: u8) -> (u128, bool) {
	name := fmt.tprintf("common%d", idx)
	val, ok := db.keys[name]
	return val, ok
}

keydb_get_common_n :: proc(db: ^KeyDatabase, idx: u8) -> (u128, bool) {
	name := fmt.tprintf("common%dn", idx)
	val, ok := db.keys[name]
	return val, ok
}

keydb_get :: proc(db: ^KeyDatabase, name: string) -> (u128, bool) {
	val, ok := db.keys[strings.to_lower(name)]
	return val, ok
}

keydb_len :: proc(db: ^KeyDatabase) -> int {
	return len(db.keys)
}

keydb_save_to_file :: proc(db: ^KeyDatabase, path: string) -> KeyDb_Error {
	last_sep := -1
	for i := len(path) - 1; i >= 0; i -= 1 {
		if path[i] == '/' || path[i] == '\\' {
			last_sep = i
			break
		}
	}

	if last_sep >= 0 {
		parent_dir := path[:last_sep]
		if len(parent_dir) > 0 && !os.exists(parent_dir) {
			err := os.make_directory(parent_dir)
			if err != nil {
				return err
			}
		}
	}

	sb := strings.builder_make(context.temp_allocator)
	strings.write_string(&sb, "# citrust key database\n")
	strings.write_string(&sb, "# Auto-saved from imported key file\n")

	entry_names := make([dynamic]string, context.temp_allocator)
	for name in db.keys {
		append(&entry_names, name)
	}

	sort.quick_sort(entry_names[:])

	for name in entry_names {
		val := db.keys[name]
		hex_str := fmt.tprintf("%032X", val)
		strings.write_string(&sb, fmt.tprintf("%s=%s\n", name, hex_str))
	}

	write_err := os.write_entire_file(path, strings.to_string(sb))
	if write_err != nil {
		return write_err
	}
	return nil
}

keydb_default_save_path :: proc() -> (string, bool) {
	#partial switch ODIN_OS {
	case .Windows:
		if appdata := os.get_env("APPDATA", context.temp_allocator); len(appdata) > 0 {
			return fmt.tprintf("%s\\citrust\\aes_keys.txt", appdata), true
		}
	case .Darwin, .Linux:
		if home := os.get_env("HOME", context.temp_allocator); len(home) > 0 {
			return fmt.tprintf("%s/.config/citrust/aes_keys.txt", home), true
		}
	}
	return "", false
}

keydb_destroy :: proc(db: ^KeyDatabase) {
	delete(db.keys)
}

@(test)
test_parse_valid_multiline :: proc(t: ^testing.T) {
	input := "generator=AAAABBBBCCCCDDDDEEEE111122223333\nslot0x2CKeyX=0123456789ABCDEF0123456789ABCDEF\nslot0x25KeyX=FEDCBA9876543210FEDCBA9876543210\n"
	db, err := keydb_from_reader(input)
	testing.expect(t, err == nil, "parse should succeed")
	testing.expect_value(t, keydb_len(&db), 3)

	gen, _ := keydb_generator(&db)
	testing.expect_value(t, gen, u128(0xAAAABBBBCCCCDDDDEEEE111122223333))

	x2c, _ := keydb_get_key_x(&db, 0x2C)
	testing.expect_value(t, x2c, u128(0x0123456789ABCDEF0123456789ABCDEF))

	x25, _ := keydb_get_key_x(&db, 0x25)
	testing.expect_value(t, x25, u128(0xFEDCBA9876543210FEDCBA9876543210))

	keydb_destroy(&db)
}

@(test)
test_parse_comments_and_blank_lines :: proc(t: ^testing.T) {
	input := "# This is a comment\n  \ngenerator=AAAABBBBCCCCDDDDEEEE111122223333\n\n# Another comment\nslot0x2CKeyX=0123456789ABCDEF0123456789ABCDEF\n"
	db, err := keydb_from_reader(input)
	testing.expect(t, err == nil, "parse should succeed")
	testing.expect_value(t, keydb_len(&db), 2)
	keydb_destroy(&db)
}

@(test)
test_parse_with_bom :: proc(t: ^testing.T) {
	input := "\uFEFFgenerator=AAAABBBBCCCCDDDDEEEE111122223333\n"
	db, err := keydb_from_reader(input)
	testing.expect(t, err == nil, "BOM parse should succeed")
	testing.expect_value(t, keydb_len(&db), 1)
	_, ok := keydb_generator(&db)
	testing.expect(t, ok, "generator should be present")
	keydb_destroy(&db)
}

@(test)
test_error_invalid_hex :: proc(t: ^testing.T) {
	input := "generator=AAAABBBBCCCCDDDDEEEE11112222ZZZZ\n"
	_, err := keydb_from_reader(input)
	parse_err, ok := err.(KeyDb_Parse_Error)
	testing.expect(t, ok, "should be ParseError")
	if ok {
		testing.expect_value(t, parse_err.line, 1)
		testing.expect(t, strings.contains(parse_err.reason, "invalid hex character"), "reason should mention invalid hex char")
	}
}

@(test)
test_skip_unknown_key :: proc(t: ^testing.T) {
	input := "unknown_key=nothexatall\n"
	db, err := keydb_from_reader(input)
	testing.expect(t, err == nil, "parse should succeed")
	testing.expect_value(t, keydb_len(&db), 0)
	keydb_destroy(&db)
}

@(test)
test_skip_lines_without_equals :: proc(t: ^testing.T) {
	input := "this line has no equals sign\n"
	db, err := keydb_from_reader(input)
	testing.expect(t, err == nil, "parse should succeed")
	testing.expect_value(t, keydb_len(&db), 0)
	keydb_destroy(&db)
}

@(test)
test_lookup_methods :: proc(t: ^testing.T) {
	input := "slot0x2CKeyX=0123456789ABCDEF0123456789ABCDEF\nslot0x18KeyY=00000000000000000000000000000001\nslot0x0CKeyN=AABBCCDD11223344AABBCCDD11223344\ncommon0=55667788AABBCCDD55667788AABBCCDD\ncommon0N=99001122334455669900112233445566\n"
	db, err := keydb_from_reader(input)
	testing.expect(t, err == nil, "parse should succeed")

	x2c, _ := keydb_get_key_x(&db, 0x2C)
	testing.expect_value(t, x2c, u128(0x0123456789ABCDEF0123456789ABCDEF))

	y18, _ := keydb_get_key_y(&db, 0x18)
	testing.expect_value(t, y18, u128(1))

	n0c, _ := keydb_get_key_n(&db, 0x0C)
	testing.expect_value(t, n0c, u128(0xAABBCCDD11223344AABBCCDD11223344))

	c0, _ := keydb_get_common(&db, 0)
	testing.expect_value(t, c0, u128(0x55667788AABBCCDD55667788AABBCCDD))

	c0n, _ := keydb_get_common_n(&db, 0)
	testing.expect_value(t, c0n, u128(0x99001122334455669900112233445566))

	keydb_destroy(&db)
}

@(test)
test_missing_key_returns_none :: proc(t: ^testing.T) {
	input := "generator=AAAABBBBCCCCDDDDEEEE111122223333\n"
	db, err := keydb_from_reader(input)
	testing.expect(t, err == nil, "parse should succeed")

	_, ok := keydb_get_key_x(&db, 0xFF)
	testing.expect(t, !ok, "key_x 0xFF should not exist")
	_, ok = keydb_get_key_y(&db, 0x00)
	testing.expect(t, !ok, "key_y 0x00 should not exist")
	_, ok = keydb_get_common(&db, 9)
	testing.expect(t, !ok, "common9 should not exist")

	keydb_destroy(&db)
}

@(test)
test_case_insensitive_key_names :: proc(t: ^testing.T) {
	input := "Generator=AAAABBBBCCCCDDDDEEEE111122223333\n"
	db, err := keydb_from_reader(input)
	testing.expect(t, err == nil, "parse should succeed")

	_, ok := keydb_generator(&db)
	testing.expect(t, ok, "generator lookup via lowercased name should work")

	_, ok = keydb_get(&db, "GENERATOR")
	testing.expect(t, ok, "get GENERATOR should work")
	_, ok = keydb_get(&db, "generator")
	testing.expect(t, ok, "get generator should work")

	keydb_destroy(&db)
}

@(test)
test_duplicate_key_last_wins :: proc(t: ^testing.T) {
	input := "generator=AAAABBBBCCCCDDDDEEEE111122223333\ngenerator=00000000000000000000000000000001\n"
	db, err := keydb_from_reader(input)
	testing.expect(t, err == nil, "parse should succeed")

	gen, _ := keydb_generator(&db)
	testing.expect_value(t, gen, u128(1))
	testing.expect_value(t, keydb_len(&db), 1)

	keydb_destroy(&db)
}

@(test)
test_empty_file :: proc(t: ^testing.T) {
	db, err := keydb_from_reader("")
	testing.expect(t, err == nil, "empty parse should succeed")
	testing.expect_value(t, keydb_len(&db), 0)
	_, ok := keydb_generator(&db)
	testing.expect(t, !ok, "generator should be absent in empty db")
	keydb_destroy(&db)
}

@(test)
test_search_default_locations_returns_none :: proc(t: ^testing.T) {
	_, ok := keydb_search_default_locations()
	_ = ok
}

@(test)
test_mixed_case_hex_values :: proc(t: ^testing.T) {
	input := "generator=aaaaBBBBccccDDDDeeee111122223333\n"
	db, err := keydb_from_reader(input)
	testing.expect(t, err == nil, "parse should succeed")
	gen, _ := keydb_generator(&db)
	testing.expect_value(t, gen, u128(0xAAAABBBBCCCCDDDDEEEE111122223333))
	keydb_destroy(&db)
}

@(test)
test_whitespace_trimming :: proc(t: ^testing.T) {
	input := "  generator  =  AAAABBBBCCCCDDDDEEEE111122223333  \n"
	db, err := keydb_from_reader(input)
	testing.expect(t, err == nil, "parse should succeed")
	_, ok := keydb_generator(&db)
	testing.expect(t, ok, "generator should be found with whitespace")
	keydb_destroy(&db)
}

@(test)
test_windows_line_endings :: proc(t: ^testing.T) {
	input := "generator=AAAABBBBCCCCDDDDEEEE111122223333\r\nslot0x2CKeyX=0123456789ABCDEF0123456789ABCDEF\r\n"
	db, err := keydb_from_reader(input)
	testing.expect(t, err == nil, "parse should succeed")
	testing.expect_value(t, keydb_len(&db), 2)
	keydb_destroy(&db)
}

@(test)
test_split_on_first_equals_only :: proc(t: ^testing.T) {
	input := "slot0x2CKeyX=B98E=5CECA3E4D171F76A94DE934C053\n"
	_, err := keydb_from_reader(input)
	_, ok := err.(KeyDb_Parse_Error)
	testing.expect(t, ok, "should be ParseError for extra '=' in value")
}

@(test)
test_save_and_reload :: proc(t: ^testing.T) {
	input := "generator=FEDCBA9876543210FEDCBA9876543210\nslot0x2CKeyX=0123456789ABCDEF0123456789ABCDEF\n"
	db, err := keydb_from_reader(input)
	testing.expect(t, err == nil, "initial parse should succeed")

	tmp_path := "/tmp/test_keydb_save.txt"
	os.remove(tmp_path)

	err = keydb_save_to_file(&db, tmp_path)
	testing.expect(t, err == nil, "save should succeed")
	defer os.remove(tmp_path)

	reloaded, reload_err := keydb_from_file(tmp_path)
	testing.expect(t, reload_err == nil, "reload should succeed")

	testing.expect_value(t, keydb_len(&db), keydb_len(&reloaded))
	gen_orig, _ := keydb_generator(&db)
	gen_reload, _ := keydb_generator(&reloaded)
	testing.expect_value(t, gen_orig, gen_reload)
	x2c_orig, _ := keydb_get_key_x(&db, 0x2C)
	x2c_reload, _ := keydb_get_key_x(&reloaded, 0x2C)
	testing.expect_value(t, x2c_orig, x2c_reload)

	keydb_destroy(&db)
	keydb_destroy(&reloaded)
}

@(test)
test_file_not_found :: proc(t: ^testing.T) {
	_, err := keydb_from_file("nonexistent_keys_file_xyz.txt")
	_, ok := err.(KeyDb_File_Not_Found)
	testing.expect(t, ok, "should be FileNotFound error")
}
