package main

import "core:fmt"
import "core:testing"

CryptoMethod :: enum {
	Original,
	Key7x,
	Key93,
	Key96,
}

crypto_method_from_flag :: proc(flag: u8) -> (CryptoMethod, bool) {
	switch flag {
	case 0x00: return .Original, true
	case 0x01: return .Key7x,   true
	case 0x0A: return .Key93,   true
	case 0x0B: return .Key96,   true
	}
	return {}, false
}

@(test)
test_crypto_method_from_flag_maps_correctly :: proc(t: ^testing.T) {
	methods := [?]struct{flag: u8, expected: CryptoMethod}{
		{0x00, .Original},
		{0x01, .Key7x},
		{0x0A, .Key93},
		{0x0B, .Key96},
	}
	for m in methods {
		got, ok := crypto_method_from_flag(m.flag)
		testing.expect(t, ok, fmt.tprintf("flag 0x%02X should be valid", m.flag))
		testing.expect_value(t, got, m.expected)
	}
	_, ok := crypto_method_from_flag(0xFF)
	testing.expect(t, !ok, "flag 0xFF should be invalid")
	_, ok = crypto_method_from_flag(0x02)
	testing.expect(t, !ok, "flag 0x02 should be invalid")
}
