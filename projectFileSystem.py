import secrets
import hashlib
import math
import json

# =========================================================
# ARIA S-Boxes + Constants
# =========================================================

# Table 1: S-box S1
S1 = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Table 1: S-box S1 Inverse
S1_inv = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

# Table 2: S-box S2
S2 = [
    0xe2, 0x4e, 0x54, 0xfc, 0x94, 0xc2, 0x4a, 0xcc, 0x62, 0x0d, 0x6a, 0x46, 0x3c, 0x4d, 0x8b, 0xd1,
    0x5e, 0xfa, 0x64, 0xcb, 0xb4, 0x97, 0xbe, 0x2b, 0xbc, 0x77, 0x2e, 0x03, 0xd3, 0x19, 0x59, 0xc1,
    0x1d, 0x06, 0x41, 0x6b, 0x55, 0xf0, 0x99, 0x69, 0xea, 0x9c, 0x18, 0xae, 0x63, 0xdf, 0xe7, 0xbb,
    0x00, 0x73, 0x66, 0xfb, 0x96, 0x4c, 0x85, 0xe4, 0x3a, 0x09, 0x45, 0xaa, 0x0f, 0xee, 0x10, 0xeb,
    0x2d, 0x7f, 0xf4, 0x29, 0xac, 0xcf, 0xad, 0x91, 0x8d, 0x78, 0xc8, 0x95, 0xf9, 0x2f, 0xce, 0xcd,
    0x08, 0x7a, 0x88, 0x38, 0x5c, 0x83, 0x2a, 0x28, 0x47, 0xdb, 0xb8, 0xc7, 0x93, 0xa4, 0x12, 0x53,
    0xff, 0x87, 0x0e, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01, 0x8e, 0x37, 0x74, 0x32, 0xca, 0xe9, 0xb1,
    0xb7, 0xab, 0x0c, 0xd7, 0xc4, 0x56, 0x42, 0x26, 0x07, 0x98, 0x60, 0xd9, 0xb6, 0xb9, 0x11, 0x40,
    0xec, 0x20, 0x8c, 0xbd, 0xa0, 0xc9, 0x84, 0x04, 0x49, 0x23, 0xf1, 0x4f, 0x50, 0x1f, 0x13, 0xdc,
    0xd8, 0xc0, 0x9e, 0x57, 0xe3, 0xc3, 0x7b, 0x65, 0x3b, 0x02, 0x8f, 0x3e, 0xe8, 0x25, 0x92, 0xe5,
    0x15, 0xdd, 0xfd, 0x17, 0xa9, 0xbf, 0xd4, 0x9a, 0x7e, 0xc5, 0x39, 0x67, 0xfe, 0x76, 0x9d, 0x43,
    0xa7, 0xe1, 0xd0, 0xf5, 0x68, 0xf2, 0x1b, 0x34, 0x70, 0x05, 0xa3, 0x8a, 0xd5, 0x79, 0x86, 0xa8,
    0x30, 0xc6, 0x51, 0x4b, 0x1e, 0xa6, 0x27, 0xf6, 0x35, 0xd2, 0x6e, 0x24, 0x16, 0x82, 0x5f, 0xda,
    0xe6, 0x75, 0xa2, 0xef, 0x2c, 0xb2, 0x1c, 0x9f, 0x5d, 0x6f, 0x80, 0x0a, 0x72, 0x44, 0x9b, 0x6c,
    0x90, 0x0b, 0x5b, 0x33, 0x7d, 0x5a, 0x52, 0xf3, 0x61, 0xa1, 0xf7, 0xb0, 0xd6, 0x3f, 0x7c, 0x6d,
    0xed, 0x14, 0xe0, 0xa5, 0x3d, 0x22, 0xb3, 0xf8, 0x89, 0xde, 0x71, 0x1a, 0xaf, 0xba, 0xb5, 0x81
]

# Table 2: S-box S2 Inverse
S2_inv = [
    0x30, 0x68, 0x99, 0x1b, 0x87, 0xb9, 0x21, 0x78, 0x50, 0x39, 0xdb, 0xe1, 0x72, 0x09, 0x62, 0x3c,
    0x3e, 0x7e, 0x5e, 0x8e, 0xf1, 0xa0, 0xcc, 0xa3, 0x2a, 0x1d, 0xfb, 0xb6, 0xd6, 0x20, 0xc4, 0x8d,
    0x81, 0x65, 0xf5, 0x89, 0xcb, 0x9d, 0x77, 0xc6, 0x57, 0x43, 0x56, 0x17, 0xd4, 0x40, 0x1a, 0x4d,
    0xc0, 0x63, 0x6c, 0xe3, 0xb7, 0xc8, 0x64, 0x6a, 0x53, 0xaa, 0x38, 0x98, 0x0c, 0xf4, 0x9b, 0xed,
    0x7f, 0x22, 0x76, 0xaf, 0xdd, 0x3a, 0x0b, 0x58, 0x67, 0x88, 0x06, 0xc3, 0x35, 0x0d, 0x01, 0x8b,
    0x8c, 0xc2, 0xe6, 0x5f, 0x02, 0x24, 0x75, 0x93, 0x66, 0x1e, 0xe5, 0xe2, 0x54, 0xd8, 0x10, 0xce,
    0x7a, 0xe8, 0x08, 0x2c, 0x12, 0x97, 0x32, 0xab, 0xb4, 0x27, 0x0a, 0x23, 0xdf, 0xef, 0xca, 0xd9,
    0xb8, 0xfa, 0xdc, 0x31, 0x6b, 0xd1, 0xad, 0x19, 0x49, 0xbd, 0x51, 0x96, 0xee, 0xe4, 0xa8, 0x41,
    0xda, 0xff, 0xcd, 0x55, 0x86, 0x36, 0xbe, 0x61, 0x52, 0xf8, 0xbb, 0x0e, 0x82, 0x48, 0x69, 0x9a,
    0xe0, 0x47, 0x9e, 0x5c, 0x04, 0x4b, 0x34, 0x15, 0x79, 0x26, 0xa7, 0xde, 0x29, 0xae, 0x92, 0xd7,
    0x84, 0xe9, 0xd2, 0xba, 0x5d, 0xf3, 0xc5, 0xb0, 0xbf, 0xa4, 0x3b, 0x71, 0x44, 0x46, 0x2b, 0xfc,
    0xeb, 0x6f, 0xd5, 0xf6, 0x14, 0xfe, 0x7c, 0x70, 0x5a, 0x7d, 0xfd, 0x2f, 0x18, 0x83, 0x16, 0xa5,
    0x91, 0x1f, 0x05, 0x95, 0x74, 0xa9, 0xc1, 0x5b, 0x4a, 0x85, 0x6d, 0x13, 0x07, 0x4f, 0x4e, 0x45,
    0xb2, 0x0f, 0xc9, 0x1c, 0xa6, 0xbc, 0xec, 0x73, 0x90, 0x7b, 0xcf, 0x59, 0x8f, 0xa1, 0xf9, 0x2d,
    0xf2, 0xb1, 0x00, 0x94, 0x37, 0x9f, 0xd0, 0x2e, 0x9c, 0x6e, 0x28, 0x3f, 0x80, 0xf0, 0x3d, 0xd3,
    0x25, 0x8a, 0xb5, 0xe7, 0x42, 0xb3, 0xc7, 0xea, 0xf7, 0x4c, 0x11, 0x33, 0x03, 0xa2, 0xac, 0x60
]

# ARIA Round Constants
C1 = [0x51, 0x7c, 0xc1, 0xb7, 0x27, 0x22, 0x0a, 0x94, 0xfe, 0x13, 0xab, 0xe8, 0xfa, 0x9a, 0x6e, 0xe0]
C2 = [0x6d, 0x3b, 0x8e, 0xbb, 0xc5, 0x44, 0x50, 0xad, 0x51, 0xda, 0x48, 0xcb, 0x2a, 0xe9, 0x1d, 0xc7]
C3 = [0xbd, 0x5e, 0x7c, 0x5a, 0xf7, 0xf8, 0x93, 0x01, 0xa5, 0x96, 0x7b, 0x90, 0x07, 0x3e, 0x22, 0x7a]


# =========================================================
# ARIA implementation 
# =========================================================

def prepare_blocks_bytes(data: bytes):
    # Prepare PKCS#7 padded 16-byte blocks from input bytes
    block_size = 16
    # Calculate padding length
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    padded_data = data + padding
    # Split into 16-byte blocks
    return [padded_data[i:i + block_size] for i in range(0, len(padded_data), block_size)]

def substitution_layer(block, round_type):
    # Apply ARIA S-box substitution for the given round type
    output = [0] * 16
    if round_type == 1:
        output[0], output[4], output[8], output[12] = S1[block[0]], S1[block[4]], S1[block[8]], S1[block[12]]
        output[1], output[5], output[9], output[13] = S2[block[1]], S2[block[5]], S2[block[9]], S2[block[13]]
        output[2], output[6], output[10], output[14] = S1_inv[block[2]], S1_inv[block[6]], S1_inv[block[10]], S1_inv[block[14]]
        output[3], output[7], output[11], output[15] = S2_inv[block[3]], S2_inv[block[7]], S2_inv[block[11]], S2_inv[block[15]]
    else:
        output[0], output[4], output[8], output[12] = S1_inv[block[0]], S1_inv[block[4]], S1_inv[block[8]], S1_inv[block[12]]
        output[1], output[5], output[9], output[13] = S2_inv[block[1]], S2_inv[block[5]], S2_inv[block[9]], S2_inv[block[13]]
        output[2], output[6], output[10], output[14] = S1[block[2]], S1[block[6]], S1[block[10]], S1[block[14]]
        output[3], output[7], output[11], output[15] = S2[block[3]], S2[block[7]], S2[block[11]], S2[block[15]]
    return output

def add_round_key(block, round_key):
    # XOR state bytes with round key bytes
    return [b ^ k for b, k in zip(block, round_key)]

def diffusion_layer(block):
    w = block
    output = [0] * 16
    output[0]  = w[3]  ^ w[4]  ^ w[6]  ^ w[8]  ^ w[9]  ^ w[13] ^ w[14]
    output[1]  = w[2]  ^ w[5]  ^ w[7]  ^ w[8]  ^ w[9]  ^ w[12] ^ w[15]
    output[2]  = w[1]  ^ w[4]  ^ w[6]  ^ w[10] ^ w[11] ^ w[12] ^ w[15]
    output[3]  = w[0]  ^ w[5]  ^ w[7]  ^ w[10] ^ w[11] ^ w[13] ^ w[14]
    output[4]  = w[0]  ^ w[2]  ^ w[5]  ^ w[8]  ^ w[11] ^ w[14] ^ w[15]
    output[5]  = w[1]  ^ w[3]  ^ w[4]  ^ w[9]  ^ w[10] ^ w[14] ^ w[15]
    output[6]  = w[0]  ^ w[2]  ^ w[7]  ^ w[9]  ^ w[10] ^ w[12] ^ w[13]
    output[7]  = w[1]  ^ w[3]  ^ w[6]  ^ w[8]  ^ w[11] ^ w[12] ^ w[13]
    output[8]  = w[0]  ^ w[1]  ^ w[4]  ^ w[7]  ^ w[10] ^ w[13] ^ w[15]
    output[9]  = w[0]  ^ w[1]  ^ w[5]  ^ w[6]  ^ w[11] ^ w[12] ^ w[14]
    output[10] = w[2]  ^ w[3]  ^ w[5]  ^ w[6]  ^ w[8]  ^ w[13] ^ w[15]
    output[11] = w[2]  ^ w[3]  ^ w[4]  ^ w[7]  ^ w[9]  ^ w[12] ^ w[14]
    output[12] = w[1]  ^ w[2]  ^ w[6]  ^ w[7]  ^ w[9]  ^ w[11] ^ w[12]
    output[13] = w[0]  ^ w[3]  ^ w[6]  ^ w[7]  ^ w[8]  ^ w[10] ^ w[13]
    output[14] = w[0]  ^ w[3]  ^ w[4]  ^ w[5]  ^ w[9]  ^ w[11] ^ w[14]
    output[15] = w[1]  ^ w[2]  ^ w[4]  ^ w[5]  ^ w[8]  ^ w[10] ^ w[15]
    return output

def aria_round(block, round_key, round_num):
    # One ARIA round: add round key, substitute, then diffuse
    block = add_round_key(block, round_key)
    round_type = 1 if round_num % 2 != 0 else 2
    block = substitution_layer(block, round_type)
    block = diffusion_layer(block)
    return block

def aria_final_round(block, round_key, final_key):
    # ARIA finalization: add, substitute (type 2), then add final key
    block = add_round_key(block, round_key)
    block = substitution_layer(block, round_type=2)
    block = add_round_key(block, final_key)
    return block

def expand_intermediate_values(master_key):
    w0 = list(master_key)
    # Expand intermediate values from master key for key schedule
    w1 = add_round_key(w0, C1)
    w1 = substitution_layer(w1, round_type=1)
    w1 = diffusion_layer(w1)

    w2 = add_round_key(w1, C2)
    w2 = substitution_layer(w2, round_type=2)
    w2 = diffusion_layer(w2)
    w2 = add_round_key(w2, w0)

    w3 = add_round_key(w2, C3)
    w3 = substitution_layer(w3, round_type=1)
    w3 = diffusion_layer(w3)
    w3 = add_round_key(w3, w1)

    return w0, w1, w2, w3

def rotl128(block, shift):
    n = int.from_bytes(bytes(block), 'big')
    shifted = ((n << shift) | (n >> (128 - shift))) & ((1 << 128) - 1)
    return list(shifted.to_bytes(16, 'big'))

def generate_round_keys(master_key):
    # Generate ARIA round keys (list of 13 keys used by encrypt/decrypt)
    w0, w1, w2, w3 = expand_intermediate_values(master_key)
    ek = []
    ek.append(add_round_key(rotl128(w0, 19), w1))
    ek.append(add_round_key(rotl128(w1, 19), w2))
    ek.append(add_round_key(rotl128(w2, 19), w3))
    ek.append(add_round_key(rotl128(w3, 19), w0))
    ek.append(add_round_key(rotl128(w0, 31), w1))
    ek.append(add_round_key(rotl128(w1, 31), w2))
    ek.append(add_round_key(rotl128(w2, 31), w3))
    ek.append(add_round_key(rotl128(w3, 31), w0))
    ek.append(add_round_key(rotl128(w0, 67), w1))
    ek.append(add_round_key(rotl128(w1, 67), w2))
    ek.append(add_round_key(rotl128(w2, 67), w3))
    ek.append(add_round_key(rotl128(w3, 67), w0))
    ek.append(add_round_key(rotl128(w0, 97), w1))
    return ek

def aria_encrypt_block(block_bytes: bytes, round_keys):
    # Encrypt a single 16-byte block using the provided ARIA round keys.
    # `block_bytes` must be exactly 16 bytes.
    state = list(block_bytes)
    for r in range(1, 12):
        state = aria_round(state, round_keys[r - 1], r)
    state = aria_final_round(state, round_keys[11], round_keys[12])
    return bytes(state)

def aria_decrypt_block(block_bytes: bytes, round_keys):
    # Decrypt a single 16-byte block using the provided ARIA round keys.
    # This applies the inverse sequence of the encryption rounds.
    state = list(block_bytes)
    state = add_round_key(state, round_keys[12])
    state = substitution_layer(state, round_type=1)
    state = add_round_key(state, round_keys[11])

    for r in range(11, 0, -1):
        state = diffusion_layer(state)
        round_type = 2 if r % 2 != 0 else 1
        state = substitution_layer(state, round_type)
        state = add_round_key(state, round_keys[r - 1])

    return bytes(state)

def aria_cbc_encrypt(plaintext: bytes, master_key: bytes, iv: bytes) -> bytes:
    # ARIA-CBC encrypt with PKCS#7 padding. Returns ciphertext (multiple of 16 bytes).
    # - plaintext: arbitrary bytes
    # - master_key: 16-byte ARIA key
    # - iv: 16-byte initialization vector
    blocks = prepare_blocks_bytes(plaintext)
    round_keys = generate_round_keys(master_key)
    prev = list(iv)
    out = []
    for block in blocks:
        x = add_round_key(list(block), prev)
        c = aria_encrypt_block(bytes(x), round_keys)
        out.append(c)
        prev = list(c)
    return b"".join(out)

def aria_cbc_decrypt(ciphertext: bytes, master_key: bytes, iv: bytes) -> bytes:
    # ARIA-CBC decrypt; expects ciphertext length multiple of 16.
    # Removes PKCS#7 padding and validates it strictly.
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be multiple of 16")
    round_keys = generate_round_keys(master_key)
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    prev = list(iv)
    out = []
    for c in blocks:
        pblk = aria_decrypt_block(c, round_keys)
        plain = add_round_key(list(pblk), prev)
        out.append(bytes(plain))
        prev = list(c)
    padded = b"".join(out)
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Bad padding")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Bad padding")
    return padded[:-pad_len]


# =========================================================
# ECC (ECDH) on secp256k1 
# =========================================================

p_curve = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a_curve = 0
b_curve = 7

Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)

n_curve = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
INF = None

def mod_inv_curve(x: int) -> int:
    # Modular inverse of x modulo p_curve (Fermat's little theorem)
    x %= p_curve
    if x == 0:
        raise ZeroDivisionError("No inverse for 0 mod p_curve")
    return pow(x, p_curve - 2, p_curve)

def is_on_curve(P):
    # Return True if EC point P satisfies the secp256k1 curve equation.
    if P is INF:
        return True
    x, y = P
    return (y * y - (x * x * x + a_curve * x + b_curve)) % p_curve == 0

def point_double(P):
    # Point doubling on the elliptic curve (return INF for point at infinity)
    if P is INF:
        return INF
    x, y = P
    if y % p_curve == 0:
        return INF
    m = ((3 * x * x + a_curve) % p_curve) * mod_inv_curve((2 * y) % p_curve) % p_curve
    x3 = (m * m - 2 * x) % p_curve
    y3 = (m * (x - x3) - y) % p_curve
    return (x3, y3)

def point_add(P, Q):
    # Add two EC points P + Q with proper handling of special cases.
    if P is INF:
        return Q
    if Q is INF:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p_curve == 0:
        return INF
    if P == Q:
        return point_double(P)
    m = ((y2 - y1) % p_curve) * mod_inv_curve((x2 - x1) % p_curve) % p_curve
    x3 = (m * m - x1 - x2) % p_curve
    y3 = (m * (x1 - x3) - y1) % p_curve
    return (x3, y3)

def scalar_mult(k: int, P):
    # Scalar multiplication (double-and-add) on the curve: computes k * P.
    if k % n_curve == 0 or P is INF:
        return INF
    if k < 0:
        x, y = P
        return scalar_mult(-k, (x, (-y) % p_curve))
    result = INF
    addend = P
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        k >>= 1
    return result

def gen_ecdh_private_key() -> int:
    # Generate a secure random private scalar in [1, n-1]
    return secrets.randbelow(n_curve - 1) + 1

def gen_ecdh_public_key(d: int):
    # Compute public key Q = d * G for private scalar d
    Q = scalar_mult(d, G)
    if Q is INF or not is_on_curve(Q):
        raise ValueError("Generated invalid public key")
    return Q

def ecdh_shared_secret(d_private: int, Q_other):
    # Compute ECDH shared point S = d_private * Q_other
    if Q_other is INF or not is_on_curve(Q_other):
        raise ValueError("Other public key is invalid")
    S = scalar_mult(d_private, Q_other)
    if S is INF:
        raise ValueError("Shared secret is INF")
    return S

def ec_point_to_bytes(P) -> bytes:
    # Serialize EC point as 64-byte big-endian x||y
    if P is INF:
        raise ValueError("Cannot encode INF")
    x, y = P
    return x.to_bytes(32, "big") + y.to_bytes(32, "big")

def bytes_to_ec_point(b: bytes):
    # Deserialize 64-byte big-endian x||y into an EC point and validate it
    if len(b) != 64:
        raise ValueError("EC point must be 64 bytes (x||y)")
    x = int.from_bytes(b[:32], "big")
    y = int.from_bytes(b[32:], "big")
    P = (x, y)
    if not is_on_curve(P):
        raise ValueError("Decoded point not on curve")
    return P

def derive_master_key_from_shared_point(S) -> bytes:
    # Derive 128-bit ARIA key from shared EC point S using SHA-256 on the x-coordinate
    sx = S[0].to_bytes(32, "big")
    digest = hashlib.sha256(b"ARIA-MASTER-KEY|" + sx).digest()
    return digest[:16]  # ARIA-128


# =========================================================
# ElGamal Signature over ffdhe2048 (RFC 7919 - ffdhe2048)
# =========================================================

P_FFDHE2048_HEX = """
FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1
D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9
7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561
2433F51F5F066ED0856365553DED1AF3B557135E7F57C935
984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735
30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB
B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19
0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61
9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73
3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA
886B423861285C97FFFFFFFFFFFFFFFF
"""
p_dh = int(P_FFDHE2048_HEX.replace("\n", "").replace(" ", "").strip(), 16)
g_dh = 2

def hash_to_int(message: bytes) -> int:
    # Hash message to integer using SHA-256 (used in ElGamal signing)
    return int.from_bytes(hashlib.sha256(message).digest(), "big")

def elgamal_keygen(p: int, g: int):
    # Generate ElGamal keypair (public tuple (p,g,y), private x)
    x = secrets.randbelow(p - 2) + 1
    y = pow(g, x, p)
    return (p, g, y), x

def modinv(a: int, m: int) -> int:
    # Multiplicative inverse of a mod m
    return pow(a, -1, m)

def elgamal_sign(message: bytes, pub, x_priv: int):
    # Create ElGamal signature (r, s) on message using private x_priv
    p, g, y = pub
    m = hash_to_int(message) % (p - 1)
    while True:
        k = secrets.randbelow(p - 2) + 1
        if math.gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = modinv(k, p - 1)
    s = (k_inv * (m - x_priv * r)) % (p - 1)
    if s == 0:
        return elgamal_sign(message, pub, x_priv)
    return (r, s)

def elgamal_verify(message: bytes, signature, pub) -> bool:
    # Verify ElGamal signature (r, s) on message using public key tuple (p,g,y)
    p, g, y = pub
    r, s = signature
    if not (1 <= r <= p - 1):
        return False
    if not (0 <= s <= p - 2):
        return False
    m = hash_to_int(message) % (p - 1)
    left = pow(g, m, p)
    right = (pow(y, r, p) * pow(r, s, p)) % p
    return left == right



# =========================================================
# Simple User Authentication
# =========================================================

USERS_DB = {}  # "table": username -> password_hash_hex

def password_hash(password: str) -> str:
    # Return a short hex hash of the password (used for simple demo auth)
    return hashlib.sha256(password.encode("utf-8")).hexdigest()[:16]

def register_user(username: str, password: str) -> None:
    # Register username with hashed password in USERS_DB
    if username in USERS_DB:
        raise ValueError(f"User '{username}' already exists")
    USERS_DB[username] = password_hash(password)

def login_user(username: str, password: str) -> bool:
    # Check username/password against USERS_DB
    if username not in USERS_DB:
        return False
    return USERS_DB[username] == password_hash(password)


# =========================================================
# Helper functions for protocol messages 
# =========================================================



def build_plaintext_sig_message(iv: bytes, plaintext: bytes) -> bytes:
    # Build the exact message that gets signed: IV || PLAINTEXT
    return iv + plaintext


# =========================================================
# Simulation of Alice & Bob secure file transfer
# =========================================================

def simulate_secure_transfer():
    # Demonstration function that simulates a full handshake,
    # ECDH key agreement, ARIA-CBC encryption, and ElGamal signing.
    print("=== Step 0: User registration + login (hash) ===")

    # Demo passwords
    alice_username, alice_password = "Alice", "1111"
    bob_username, bob_password = "Bob", "2222"

    # Register users (store only hashes in "table")
    register_user(alice_username, alice_password)
    register_user(bob_username, bob_password)

    print("[DB] Stored users (username -> sha256(password)):")
    for u, h in USERS_DB.items():
        print(f"  {u} -> {h}")

    # Simulate login
    print("\n[Alice] Logging in...")
    if not login_user(alice_username, alice_password):
        print("Alice: LOGIN FAILED")
        return
    print("Alice: LOGIN OK")

    print("\n[Bob] Logging in...")
    if not login_user(bob_username, bob_password):
        print("Bob: LOGIN FAILED")
        return
    print("Bob: LOGIN OK")
    
    
    print("\n=== Step 1: Long-term ElGamal key generation ===")    
    
    # Alice long-term ElGamal keys (signature)
    alice_pub, alice_priv = elgamal_keygen(p_dh, g_dh)
    # Bob long-term ElGamal keys (signature)
    bob_pub, bob_priv = elgamal_keygen(p_dh, g_dh)

    # alice_pub and bob_pub are tuples: (p, g, y)
    print("[Alice] ElGamal long-term public key:")
    print(f"  p (modulus) = ffdhe2048 (RFC 7919)")
    print(f"  g (generator) = {alice_pub[1]}")
    print(f"  y_A (public) = {alice_pub[2]}")
    print()
    print("[Bob] ElGamal long-term public key:")
    print(f"  p (modulus) = ffdhe2048 (RFC 7919)")
    print(f"  g (generator) = {bob_pub[1]}")
    print(f"  y_B (public) = {bob_pub[2]}")
    print()

    # =====================================================
    # Step 2: Handshake + identity authentication
    # =====================================================
    print("=== Step 2: Handshake + identity authentication ===")

    # ----- Alice side: create ephemeral ECDH key and sign handshake -----
    dA = gen_ecdh_private_key()
    QA = gen_ecdh_public_key(dA)  # Alice's ephemeral public key (QS)

    print("[Alice] Generated ephemeral ECDH key pair:")
    print(f"  d_A (private) = (hidden)")
    print(f"  Q_A.x = {QA[0]:#x}")
    print(f"  Q_A.y = {QA[1]:#x}")

    QA_bytes = ec_point_to_bytes(QA)          # message = only Q_A bytes (64 bytes)
    sig_hs_A = elgamal_sign(QA_bytes, alice_pub, alice_priv)
    
    print("[Network] Alice → Bob sends: Q_A (point) + signature (r,s)")
    wire_QA_point = QA
    wire_sig_A = sig_hs_A
    print()



    # ----- Bob side: verify Alice, then create his own ephemeral ECDH key -----
    # Bob receives Q_A point + signature
    QA_recv = wire_QA_point
    sig_hs_A_recv = wire_sig_A
    
    print("[Bob] Received Q_A (point):")
    print(f"  Q_A.x = {QA_recv[0]:#x}")
    print(f"  Q_A.y = {QA_recv[1]:#x}")
    
    # validate point
    if not is_on_curve(QA_recv):
        print("Bob: ERROR - received Q_A is not on curve")
        return
    
    # convert to bytes for signature verification (message = Q_A_bytes)
    QA_bytes_verify = ec_point_to_bytes(QA_recv)
    
    print("[Bob] Verifying Alice signature on Q_A_bytes (x||y)...")
    if not elgamal_verify(QA_bytes_verify, sig_hs_A_recv, alice_pub):
        print("Bob: ERROR - failed to verify Alice signature")
        return
    print("Bob: verified Alice identity successfully")
    print()



    dB = gen_ecdh_private_key()
    QB = gen_ecdh_public_key(dB)  # Bob's ephemeral public key (QR)

    print("[Bob] Generated ephemeral ECDH key pair:")
    print(f"  d_B (private) = (hidden)")
    print(f"  Q_B.x = {QB[0]:#x}")
    print(f"  Q_B.y = {QB[1]:#x}")

    QB_bytes = ec_point_to_bytes(QB)
    sig_hs_B = elgamal_sign(QB_bytes, bob_pub, bob_priv)
    
    print("[Network] Bob → Alice sends: Q_B (point) + signature (r,s)")
    wire_QB_point = QB
    wire_sig_B = sig_hs_B
    print()



    # Alice receives Q_B point + signature
    QB_recv = wire_QB_point
    sig_hs_B_recv = wire_sig_B
    
    print("[Alice] Received Q_B (point):")
    print(f"  Q_B.x = {QB_recv[0]:#x}")
    print(f"  Q_B.y = {QB_recv[1]:#x}")
    
    # validate point
    if not is_on_curve(QB_recv):
        print("Alice: ERROR - received Q_B is not on curve")
        return
    
    # convert to bytes for signature verification
    QB_bytes_verify = ec_point_to_bytes(QB_recv)
    
    print("[Alice] Verifying Bob signature on Q_B_bytes (x||y)...")
    if not elgamal_verify(QB_bytes_verify, sig_hs_B_recv, bob_pub):
        print("Alice: ERROR - failed to verify Bob signature")
        return
    print("Alice: verified Bob identity successfully")
    print()



    # =====================================================
    # Step 3: Derive shared symmetric key via ECDH
    # =====================================================
    print("=== Step 3: Deriving shared symmetric key (ECDH → ARIA key) ===")

    # Alice computes S = dA * QB
    S_alice = ecdh_shared_secret(dA, QB)
    # Bob computes S = dB * QA
    S_bob = ecdh_shared_secret(dB, QA)

    if S_alice != S_bob:
        print("ERROR: ECDH shared points do not match!")
        return

    print("[Alice & Bob] ECDH shared point S:")
    print(f"  S.x = {S_alice[0]:#x}")
    print(f"  S.y = {S_alice[1]:#x}")

    master_key_alice = derive_master_key_from_shared_point(S_alice)
    master_key_bob = derive_master_key_from_shared_point(S_bob)

    if master_key_alice != master_key_bob:
        print("ERROR: derived master keys do not match! ECDH failure.")
        return

    master_key = master_key_alice
    print("Alice & Bob: shared symmetric key established (ARIA-128)")
    print(f"  ARIA-128 key (hex) = {master_key.hex()}")
    print()

    # =====================================================
    # Step 4: Alice encrypts original.txt and signs payload
    # =====================================================
    print("=== Step 4: Alice encrypts and signs file ===")

    try:
        with open("original.txt", "rb") as f:
            plaintext = f.read()
    except FileNotFoundError:
        print("ERROR: original.txt not found. Please create it and run again.")
        return

    print(f"[Alice] Loaded original.txt ({len(plaintext)} bytes).")

    # Generate random IV for ARIA-CBC (no external library, using secrets)
    iv = secrets.token_bytes(16)
    print("[Alice] Generated random IV for ARIA-CBC:")
    print(f"  IV (hex) = {iv.hex()}")

    ciphertext = aria_cbc_encrypt(plaintext, master_key, iv)
    print(f"[Alice] Ciphertext length = {len(ciphertext)} bytes.")

    # Sign ONLY (IV || PLAINTEXT)
    sig_msg = build_plaintext_sig_message(iv, plaintext)
    sig_payload = elgamal_sign(sig_msg, alice_pub, alice_priv)
    
    print("[Alice] Signature is over ORIGINAL data (IV || PLAINTEXT):")
    print("  Format: IV + PLAINTEXT")
    print(f"  Signature (r,s) = ({sig_payload[0]}, {sig_payload[1]})")
    print()


    # Prepare encrypted.txt as JSON: iv_hex, ciphertext_hex, signature (r, s)
    enc_obj = {
        "iv_hex": iv.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "signature": {
            "r": str(sig_payload[0]),
            "s": str(sig_payload[1]),
        },
    }

    with open("encrypted.txt", "w", encoding="utf-8") as f:
        json.dump(enc_obj, f, indent=2)

    print("Alice: file encrypted and signed")
    print("Alice: encrypted.txt created (contains IV, ciphertext, signature)")
    print()

    # =====================================================
    # Step 5: Bob verifies payload and decrypts
    # =====================================================
    print("=== Step 5: Bob verifies and decrypts encrypted.txt ===")

    try:
        with open("encrypted.txt", "r", encoding="utf-8") as f:
            enc_loaded = json.load(f)
    except FileNotFoundError:
        print("ERROR: encrypted.txt not found.")
        return

    iv_b = bytes.fromhex(enc_loaded["iv_hex"])
    ciphertext_b = bytes.fromhex(enc_loaded["ciphertext_hex"])
    r_b = int(enc_loaded["signature"]["r"])
    s_b = int(enc_loaded["signature"]["s"])
    sig_payload_b = (r_b, s_b)

    print("[Bob] Loaded encrypted.txt:")
    print(f"  IV (hex) = {iv_b.hex()}")
    print(f"  Ciphertext length = {len(ciphertext_b)} bytes")
    print(f"  Signature (r,s) = ({r_b}, {s_b})")

    # Decrypt using master_key_bob (same as Alice's)
    decrypted = aria_cbc_decrypt(ciphertext_b, master_key_bob, iv_b)


    # Verify signature on (IV || DECRYPTED_PLAINTEXT)
    sig_msg_b = build_plaintext_sig_message(iv_b, decrypted)
    
    print("[Bob] Verifying signature on ORIGINAL data (IV || PLAINTEXT)...")
    print("  Format: IV + decrypted_plaintext")
    print(f"  Signature message length (bytes) = {len(sig_msg_b)}")
    
    if not elgamal_verify(sig_msg_b, sig_payload_b, alice_pub):
        print("Bob: ERROR - invalid signature on plaintext! Aborting.")
        return
    
    print("Bob: signature verified (plaintext + IV)")
    print()


    with open("decrypted.txt", "wb") as f:
        f.write(decrypted)

    print("Bob: file decrypted and saved as decrypted.txt")
    print(f"  Decrypted length = {len(decrypted)} bytes")
    print()

    # =====================================================
    # Step 6: Optional integrity check: original vs decrypted
    # =====================================================
    print("=== Step 6: Comparing original.txt and decrypted.txt ===")

    if decrypted == plaintext:
        print("Transfer completed successfully: original.txt == decrypted.txt")
    else:
        print("ERROR: decrypted file does not match original!")


if __name__ == "__main__":
    simulate_secure_transfer()
















