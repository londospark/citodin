package main

import "core:crypto/aes"
import "core:bytes"
import "core:encoding/endian"
import "core:testing"

rol128 :: proc(val: u128, shift: u32) -> u128 {
	s := shift % 128
	return (val << s) | (val >> (128 - s))
}

derive_normal_key :: proc(key_x, key_y, constant: u128) -> u128 {
	rotated_x := rol128(key_x, 2)
	xored := rotated_x ~ key_y
	added := xored + constant
	return rol128(added, 87)
}

u128_to_be_bytes :: proc(val: u128) -> [16]u8 {
	bytes: [16]u8
	endian.unchecked_put_u64be(bytes[0:], u64(val >> 64))
	endian.unchecked_put_u64be(bytes[8:], u64(val))
	return bytes
}

be_bytes_to_u128 :: proc(bytes: ^[16]u8) -> u128 {
	hi := u128(endian.unchecked_get_u64be(bytes[0:]))
	lo := u128(endian.unchecked_get_u64be(bytes[8:]))
	return (hi << 64) | lo
}

aes_ctr_decrypt :: proc(key: ^[16]u8, iv: u128, data: []u8) {
	ctx: aes.Context_CTR
	iv_bytes := u128_to_be_bytes(iv)
	aes.init_ctr(&ctx, key[:], iv_bytes[:])
	aes.xor_bytes_ctr(&ctx, data, data)
	aes.reset_ctr(&ctx)
}

@(test)
test_rol128_basic :: proc(t: ^testing.T) {
	testing.expect_value(t, rol128(1, 1), u128(2))
	testing.expect_value(t, rol128(1, 2), u128(4))
	testing.expect_value(t, rol128(1, 127), u128(1) << 127)
}

@(test)
test_rol128_wraparound :: proc(t: ^testing.T) {
	msb_set := u128(0x80000000_00000000_00000000_00000000)
	testing.expect_value(t, rol128(msb_set, 1), u128(1))
}

@(test)
test_rol128_edge_cases :: proc(t: ^testing.T) {
	testing.expect_value(t, rol128(42, 0), u128(42))
	testing.expect_value(t, rol128(42, 128), u128(42))
	testing.expect_value(t, rol128(0, 10), u128(0))
}

@(test)
test_rol128_large_shifts :: proc(t: ^testing.T) {
	testing.expect_value(t, rol128(5, 256), u128(5))
	testing.expect_value(t, rol128(5, 129), rol128(5, 1))
}

@(test)
test_derive_normal_key_known_vector :: proc(t: ^testing.T) {
	key_x   := u128(0x12345678_9ABCDEF0_11111111_22222222)
	key_y   := u128(0xAAAAAAAA_BBBBBBBB_CCCCCCCC_DDDDDDDD)
	constant := u128(0x1F_F9E9AA_C5FE0408_024591DC_5D52768A)

	rotated_x := rol128(key_x, 2)
	xored := rotated_x ~ key_y
	added := xored + constant
	expected := rol128(added, 87)

	result := derive_normal_key(key_x, key_y, constant)
	testing.expect_value(t, result, expected)
}

@(test)
test_aes_ctr_decrypt_known_vector :: proc(t: ^testing.T) {
	key := [16]u8{
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
	}

	iv := be_bytes_to_u128(&[16]u8{
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
	})

	plaintext := [16]u8{
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
		0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
	}

	expected_ciphertext := [16]u8{
		0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
		0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
	}

	data := plaintext
	aes_ctr_decrypt(&key, iv, data[:])
	testing.expect(t, 	bytes.equal(data[:], expected_ciphertext[:]),
		"AES-CTR decrypt should match expected ciphertext")

	aes_ctr_decrypt(&key, iv, data[:])
	testing.expect(t, 	bytes.equal(data[:], plaintext[:]),
		"AES-CTR double-decrypt should restore plaintext")
}

@(test)
test_u128_conversion_roundtrip :: proc(t: ^testing.T) {
	original := u128(0x12345678_9ABCDEF0_FEDCBA98_76543210)
	bytes := u128_to_be_bytes(original)
	restored := be_bytes_to_u128(&bytes)
	testing.expect_value(t, original, restored)
}
