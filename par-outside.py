#!/usr/bin/env python3

# Generates "par-outside" wrappers for RAR or ZIP files: these files have Par3
# packets on the outside and can be parsed as valid Par3 files, while (ab)using
# the peculiarities of RAR and ZIP file formats to make them valid RAR and ZIP
# files at the same time.
#
# For this I introduce a custom "embedded data" packet (type "TestEmb\0") which
# is a little similar to a Data packet except it stores an arbitrary amount of
# data in place, and not just one chunk.
#
# Currently the embed packet contains just the file data as the packet body; a
# more robust implementation might include metadata like original filename and
# MIME type, and/or instructions how to reassemble the original file from the
# embedded packet data.
#
# See the Main() function at the bottom of the file for more details.

from dataclasses import dataclass
from io import Writer
from typing import Iterable
from blake3 import blake3
from parser import (PAR3_PKT_HEAD_MAGIC, PAR3_PKT_HEAD_FORMAT, PAR3_PKT_HEAD_SIZE)
from crc64iso import crc64iso
import random
import os
import struct
import sys

GF16_BYTES = 2
GF16_POLY  = 0x1100B

CREATOR = b'https://github.com/maksverver/par-python/blob/master/par-outside.py'

PACKET_TYPE_CREATOR  = b'PAR CRE\0'
PACKET_TYPE_ROOT     = b'PAR ROO\0'
PACKET_TYPE_FILE     = b'PAR FIL\0'
PACKET_TYPE_START    = b'PAR STA\0'
PACKET_TYPE_EXT_DATA = b'PAR EXT\0'
PACKET_TYPE_CAUCHY   = b'PAR CAU\0'
PACKET_TYPE_RECOVERY = b'PAR REC\0'
PACKET_TYPE_EMBED    = b'TestEmb\0'

INPUT_SET_ID_SIZE     =  8  # bytes
PACKET_TYPE_SIZE      =  8  # bytes
ROLLING_HASH_SIZE     =  8  # bytes
FINGERPRINT_HASH_SIZE = 16  # bytes

# Pick a random input set id
input_set_id = struct.pack('<Q', random.randrange(256**ROLLING_HASH_SIZE))

target_input_block_count = 100
recovery_block_count     =  10

def CalculateBlockSize(protected_size):
    global block_size, block_count
    block_size = (protected_size + target_input_block_count - 1) // target_input_block_count
    if block_size == 0:
        # Block size of at least 1 element
        block_size = GF16_BYTES
    elif block_size % GF16_BYTES != 0:
        # Round up to a multiple of the block size
        block_size += GF16_BYTES - block_size % GF16_BYTES
    block_count = (protected_size // block_size) + ((protected_size % block_size) >= 40)

def RollingHash(data):
    return struct.pack('<Q', crc64iso(data))

assert RollingHash(b'123456789').hex() == '0110a475c75609b9'  # little endian byte order

def FingerprintHash(data):
    return blake3(data).digest(FINGERPRINT_HASH_SIZE)

@dataclass
class Packet:
    type: bytes
    body: bytes
    fingerprint_hash: bytes

def CalculatePacketHash(type, body):
    h = blake3()
    h.update(struct.pack('Q', len(body) + PAR3_PKT_HEAD_SIZE))
    h.update(input_set_id)
    h.update(type)
    h.update(body)
    return h.digest(FINGERPRINT_HASH_SIZE)

def CreatePacket(type: bytes, body: bytes):
    assert isinstance(type, bytes) and len(type) == PACKET_TYPE_SIZE
    assert isinstance(body, bytes)
    packet = Packet(type=type, body=body, fingerprint_hash=CalculatePacketHash(type, body))
    return packet

def EncodeHeader(packet: Packet) -> bytes:
    return PAR3_PKT_HEAD_MAGIC + struct.pack(PAR3_PKT_HEAD_FORMAT, packet.fingerprint_hash, PAR3_PKT_HEAD_SIZE + len(packet.body), input_set_id, packet.type)

def EncodePacket(packet: Packet):
    return EncodeHeader(packet) + packet.body

def WritePacket(out: Writer[bytes], packet):
    out.write(EncodeHeader(packet))
    out.write(packet.body)

def CreateCreatorPacket() -> Packet:
    return CreatePacket(PACKET_TYPE_CREATOR, CREATOR)

def CreateStartPacket() -> Packet:
    parent_input_set_id = bytes(INPUT_SET_ID_SIZE)
    parent_root_packet  = bytes(FINGERPRINT_HASH_SIZE)
    body = struct.pack('<8s16sQBH', parent_input_set_id, parent_root_packet, block_size, GF16_BYTES, GF16_POLY & 0xffff)
    return CreatePacket(PACKET_TYPE_START, body)

def CreateMatrixPacket() -> Packet:
    body = struct.pack('<QQQ', 0, 0, recovery_block_count)
    return CreatePacket(PACKET_TYPE_CAUCHY, body)

def UnprotectedChunk(length):
    return struct.pack('<QQ', 0, length)

def ProtectedChunk(data, first_block_index):
    length = len(data)
    parts = [struct.pack('<Q', length)]
    full_block_count = length // block_size
    if full_block_count > 0:
        parts.append(struct.pack('<Q', first_block_index))
    tail = data[full_block_count * block_size:]
    if len(tail) < 40:
        parts.append(tail)
    else:
        parts.append(RollingHash(tail[:40]))
        parts.append(FingerprintHash(tail))
        tail_block_index  = first_block_index + full_block_count
        tail_block_offset = 0
        parts.append(struct.pack('<QQ', tail_block_index, tail_block_offset))
    return b''.join(parts)

def SliceData(data: bytes) -> Iterable[bytes]:
    for i in range(0, len(data), block_size):
        j = i + block_size
        if j <= len(data):
            yield data[i:j]
        elif len(data) - i >= 40:
            # Pad with zeros to full block size
            yield data[i:len(data)] + bytes(j - len(data))
        else:
            # Tail smaller than 40 bytes; don't generate a slice.
            pass

def GenerateRecoveryDataPacket(root_hash, matrix_hash, index, data):
    body = struct.pack('<16s16sQ', root_hash, matrix_hash, index) + data
    return CreatePacket(PACKET_TYPE_RECOVERY, body)

def CreateExternalDataPacket(first_block_index: int, blocks: Iterable[bytes]) -> Packet:
    parts = [struct.pack('<Q', first_block_index)]
    for block in blocks:
        assert len(block) == block_size
        parts.append(RollingHash(block))
        parts.append(FingerprintHash(block))
    return CreatePacket(PACKET_TYPE_EXT_DATA, b''.join(parts))

def CreateFilePacket(filename: str, rolling_hash_16k, protected_data_hash, chunks) -> Packet:
    encoded_filename = filename.encode()
    parts = [
        struct.pack('<H', len(encoded_filename)),
        encoded_filename,
        rolling_hash_16k,  # rolling hash of first 16 k (empty means not known)
        protected_data_hash,
        struct.pack('<B', 0),  # options
    ] + chunks
    return CreatePacket(PACKET_TYPE_FILE, b''.join(parts))

# Entries is a sequence of bytestrings,the fingerprint hashes of the file packets
def CreateRootPacket(block_count: int, entries: Iterable[bytes]) -> Packet:
    assert all(len(entry) == FINGERPRINT_HASH_SIZE for entry in entries)
    attributes = 0  # relative dir
    option_count = 0
    body = struct.pack('<QBI', block_count, attributes, option_count) + b''.join(entries)
    return CreatePacket(PACKET_TYPE_ROOT, body)

def GenerateRecoverySlices(input_slices: Iterable[bytes]) -> list[bytes]:
    if recovery_block_count == 0:
        return []

    # Lazily import these only when generating recovery slices:
    import numpy as np
    import galois

    dt = np.dtype('<H')  # little-endian unsigned short (16 bits)
    F = galois.GF(256 ** GF16_BYTES, irreducible_poly=GF16_POLY)
    # Sanity check roundtrip; this might not hold on big endian architectures?
    assert block_size % GF16_BYTES == 0
    assert F(np.array([0x0123, 0x4567], dtype=dt)).tobytes() == b'\x23\x01\x67\x45'

    # Convert input slices into a 2D field matrix of dimensions block_count x block_size
    input_data = F([np.frombuffer(slice, dtype=dt) for slice in input_slices])

    # Cauchy generator matrix G defined as G[i,j] = F(1)/F((MAX - j) ^ F(i))
    MAX = 256 ** GF16_BYTES - 1
    G = F(1)/F(np.arange(block_count, dtype=dt)[None,:] ^ np.arange(MAX, MAX - recovery_block_count, -1, dtype=dt)[:,None])
    return [row.tobytes() for row in G @ input_data]

def EmbedFile(embedded_data, output_filename, append=False):
    protected_data = EncodePacket(CreatePacket(PACKET_TYPE_EMBED, embedded_data))
    CalculateBlockSize(len(protected_data))

    creator_packet = CreateCreatorPacket()
    start_packet   = CreateStartPacket()
    matrix_packet  = CreateMatrixPacket()
    external_data_packet = CreateExternalDataPacket(0, SliceData(protected_data))

    # Rolling hash of first 16 KiB but only if the entire region is protected
    if append or len(protected_data) < 16384:
        file_rolling_hash_16k = bytes(ROLLING_HASH_SIZE)
    else:
        file_rolling_hash_16k = RollingHash(protected_data[:16384])

    recovery_slices = GenerateRecoverySlices(SliceData(protected_data))

    # Generate file and root packets. This requires two passes because the file
    # chunk sizes depend on the size of the generated output.
    unprotected_size = 1
    for _ in ('pass1', 'pass2'):
        stored_unprotected_size = unprotected_size
        file_chunks = []
        if not append:
            file_chunks.append(ProtectedChunk(protected_data, 0))
        file_chunks.append(UnprotectedChunk(stored_unprotected_size))
        if append:
            file_chunks.append(ProtectedChunk(protected_data, 0))
        file_packet = CreateFilePacket(output_filename, file_rolling_hash_16k, FingerprintHash(protected_data), file_chunks)
        root_packet = CreateRootPacket(block_count, [file_packet.fingerprint_hash])
        recovery_packets = [
            GenerateRecoveryDataPacket(root_packet.fingerprint_hash, matrix_packet.fingerprint_hash, i, slice)
            for i, slice in enumerate(recovery_slices)]
        # Packets in order recommended by the Par3 spec:
        unprotected_packets = [
            creator_packet,
            start_packet,
            matrix_packet,
            root_packet,
            file_packet,
            external_data_packet
        ] + recovery_packets
        unprotected_size = sum(PAR3_PKT_HEAD_SIZE + len(packet.body) for packet in unprotected_packets)
    assert stored_unprotected_size == unprotected_size

    with open(output_filename, 'wb') as f:
        if not append:
            f.write(protected_data)
        for packet in unprotected_packets:
            WritePacket(f, packet)
        if append:
            f.write(protected_data)

def FindEocd(zip_data):
    for i in range(len(zip_data) - 4, -1, -1):
        if zip_data[i:i+4] == b'PK\5\6':
            return i

def AdjustZipFileOffsets(zip_data, delta):
    # Note this currently only supports the classic central directory records
    # and end of central directory record; it doesn't handle Zip64 extensions.
    eocd_offset = FindEocd(zip_data)
    assert eocd_offset is not None
    cd_size, cd_offset = struct.unpack('<II', zip_data[eocd_offset + 12:eocd_offset + 20])
    zip_data = bytearray(zip_data)
    zip_data[eocd_offset + 16:eocd_offset + 20] = struct.pack('<I', cd_offset + delta)
    while cd_size > 0:
        magic = zip_data[cd_offset:cd_offset + 4]
        if magic == 'PK\5\5':
            # Digital signature
            break
        assert magic == b'PK\1\2'  # File header
        assert cd_size >= 46
        filename_length, extra_length, comment_length = struct.unpack('<HHH', zip_data[cd_offset + 28:cd_offset + 34])
        local_header_offset, = struct.unpack('<I', zip_data[cd_offset + 42:cd_offset + 46])
        zip_data[cd_offset + 42:cd_offset + 46] = struct.pack('<I', local_header_offset + delta)
        size = 46 + filename_length + extra_length + comment_length
        assert size <= cd_size
        cd_size -= size
        cd_offset += size
    return bytes(zip_data)

def ReadFile(input_filename: str) -> bytes:
    with open(input_filename, 'rb') as f:
        return f.read()

def Main():
    # Embedded RAR structure:
    #
    #   1. Embed packet with original RAR file
    #   2. All standard PAR3 packets
    #
    # The protected region is the first half of the file, covering the embed
    # header and its RAR file contents.
    #
    # This works because RAR allows up to 1 MiB of random data in front of the
    # RAR file identication magic, usually for self-extracting executables, but
    # in this case we use it for the embed packet header.
    EmbedFile(ReadFile('test.rar'), 'embedded.rar.par3', append=False)

    # Embedded ZIP structure:
    #
    #   1. All standard PAR3 packets
    #   2. Embed packet with original Zip file
    #
    # The protected region is the second half of the file, covering the embed
    # header and its ZIP file contents.
    #
    # This works because ZIP files store the central directory at the end of the
    # file, and ZIP readers usually ignore extra data prepended at the front.
    # This is not explicitly required by the standard, and may trigger a warning
    # upon opening, but it is widely supported in practice.
    zip_input = 'test.zip'
    zip_output1 = 'embedded.zip.par3'
    zip_output2 = 'embedded2.zip.par3'
    zip_data = ReadFile(zip_input)
    EmbedFile(zip_data, zip_output1, append=True)

    # To improve compatibility further, we can also adjust the file positions
    # so they match the locations in the new file. This prevents warnings, but
    # makes it harder to recover the original ZIP file.
    delta = (os.path.getsize(zip_output1) - os.path.getsize(zip_input) +
        len(zip_output2) - len(zip_output1))
    EmbedFile(AdjustZipFileOffsets(zip_data, delta), zip_output2, append=True)

if __name__ == '__main__':
    Main()
