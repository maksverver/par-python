#!/usr/bin/env python3

# PAR2 parser

from parser import (
    BodyReader, HashingBodyReader, PacketHeader, ReadPackets,
    Unicode, ReadFull, ReadExact, ReadStruct,
)

from collections import defaultdict
from dataclasses import dataclass
import glob
import hashlib
from pathlib import Path
import os
import sys
import traceback
from typing import Any


# Core packet types
PAR2_PKT_TYP_MAIN     = b'PAR 2.0\0Main\0\0\0\0'
PAR2_PKT_TYP_FILEDESC = b'PAR 2.0\0FileDesc'
PAR2_PKT_TYP_IFSC     = b'PAR 2.0\0IFSC\0\0\0\0'    # Input file slice checksum
PAR2_PKT_TYP_RECVSLIC = b'PAR 2.0\0RecvSlic'        # Recovery file slice
PAR2_PKT_TYP_CREATOR  = b'PAR 2.0\0Creator\0'

# Optional packet types
PAR2_PKT_TYP_UNIFILEN = b'PAR 2.0\0UniFileN'
PAR2_PKT_TYP_COMMASCI = b'PAR 2.0\0CommASCI'
PAR2_PKT_TYP_COMMUNI  = b'PAR 2.0\0CommUni'
PAR2_PKT_TYP_FILESLIC = b'PAR 2.0\0FileSlic'        # Input file slice
PAR2_PKT_TYP_RFSC     = b"PAR 2.0\0RFSC\0\0\0\0"    # Recovery file slice checksum
PAR2_PKT_TYP_PKDMAIN  = b'PAR 2.0\0PkdMain\0'       # Packed main
PAR2_PKT_TYP_PKDRECVS = b'PAR 2.0\0PkdRecvS'        # Packed recovery slice


@dataclass
class MainPacket:
    slice_size: int
    file_count: int
    recovery_file_ids: list[bytes]
    ignored_file_ids: list[bytes]

@dataclass
class FileDescPacket:
    file_id: bytes
    md5: bytes          # MD5 hash of the entire file
    md5_16k: bytes      # MD5 hash of the first 16 KiB
    file_size: int      # Size of the file in bytes
    path: bytes

@dataclass
class IfscPacket:       # Input File Slice Checksums
    file_id: bytes
    checksums: list[bytes]

@dataclass
class RecvSlicPacket:
    exp: int
    data: bytes

    def __str__(self):
        return f'RecvSlicPacket(exp={self.exp}, data=omitted)'

@dataclass
class CreatorPacket:
    creator: bytes

    def __str__(self):
        return f'CreatorPacket(creator={Unicode(self.creator)})'

@dataclass
class CommAsciPacket:
    comment: bytes

    def __str__(self):
        return f'CommAsciPacket(comment={Unicode(self.comment)})'


class ParScanner:
    def __init__(self):
        self.handlers = {
            PAR2_PKT_TYP_MAIN: self.HandleMain,
            PAR2_PKT_TYP_IFSC: self.HandleIFSC,
            PAR2_PKT_TYP_FILEDESC: self.HandleFileDesc,
            PAR2_PKT_TYP_RECVSLIC: self.HandleRecvSlic,
            PAR2_PKT_TYP_CREATOR: self.HandleCreator,
            PAR2_PKT_TYP_COMMASCI: self.HandleCommAscii,
        }
        self.packets_by_rsid = defaultdict(dict)

    def HandlePacket(self, head: PacketHeader, r: HashingBodyReader):
        # Only handles PAR2 for now
        if head.ver != 2:
            return

        packets = self.packets_by_rsid[head.rsid]
        if head in packets:
            #print(f'INFO: ignoring duplicated packet type "{Unicode(head.ptyp)}"', file=sys.stderr)
            return

        handler = self.handlers.get(head.ptyp)
        if handler is None:
            print(f'INFO: ignoring unrecognized packet type "{Unicode(head.ptyp)}"', file=sys.stderr)
            return

        # Try to parse the packet
        packet = handler(head, r)
        if not packet:
            return  # Packet was not processed. Error should have been printed by handler

        # Check that the checksum is correct
        # TODO: this duplicates ReadPackets() functionality
        csum = r.finishhash().digest()
        if csum != head.csum:
            print(f'WARNING: packet of type {Unicode(head.ptyp)} failed checksum (expected: {head.csum.hex()} computed: {csum.hex()})', file=sys.stderr)
            return

        # All good! Keep it.
        packets[head] = packet

    def HandleMain(self, head: PacketHeader, r: BodyReader) -> MainPacket | None:
        slice_size, file_count = ReadStruct(r, '<QI')
        rest = r.readall()
        if len(rest) < 16*file_count or len(rest) % 16 != 0:
            print('ERROR: main packet invalid', file=sys.stderr)
            return None
        recovery_file_ids = [rest[i:i+16] for i in range(0, 16*file_count, 16)]
        ignored_file_ids  = [rest[i:i+16] for i in range(16*file_count, len(rest), 16)]
        return MainPacket(slice_size=slice_size, file_count=file_count,
                recovery_file_ids=recovery_file_ids, ignored_file_ids=ignored_file_ids)

    def HandleFileDesc(self, head: PacketHeader, r: BodyReader) -> FileDescPacket:
        file_id, md5, md5_16k, file_size = ReadStruct(r, '<16s16s16sQ')
        path = r.readall().rstrip(b'\0')
        return FileDescPacket(file_id=file_id, md5=md5, md5_16k=md5_16k,
                file_size=file_size, path=path)

    def HandleIFSC(self, head: PacketHeader, r: BodyReader) -> IfscPacket:
        file_id, = ReadStruct(r, '<16s')
        checksums = []
        while r.size_left > 0:
            checksums.append(ReadStruct(r, '<16sI'))
        return IfscPacket(file_id=file_id, checksums=checksums)

    def HandleRecvSlic(self, head: PacketHeader, r: BodyReader) -> RecvSlicPacket:
        # TODO later: refactor so we don't read the entire slice into memory!
        exp, = ReadStruct(r, '<I')
        data = r.readall()
        return RecvSlicPacket(exp=exp, data=data)

    def HandleCreator(self, head: PacketHeader, r: BodyReader) -> CreatorPacket:
        return CreatorPacket(creator=r.readall().rstrip(b'\0'))

    def HandleCommAscii(self, head: PacketHeader, r: BodyReader) -> CommAsciPacket:
        return CommAsciPacket(comment=r.readall().rstrip(b'\0'))

    def GetPacketsByRsid(self) -> dict[bytes, dict[PacketHeader, Any]]:
        return self.packets_by_rsid


def ExtractInputSlices(file_desc, slice_size) -> list[bytes] | None:
    # TODO: should sanitize file path to prevent accessing outside of current directory etc.
    path = Path(input_path, Unicode(file_desc.path))
    try:
        file_size = os.path.getsize(path)
    except Exception as e:
        print(f'ERROR: Could not get file size of {path}', file=sys.stderr)
        traceback.print_exception(e)  # for debugging
        return None

    if file_size != file_desc.file_size:
        print(f'ERROR: invalid file size of {path} (expected: {file_desc.file_size}, actual: {file_size})', file=sys.stderr)
        return None

    if not path.exists():
        print(f'WARNING: File does not exist: {path}', file=sys.stderr)
        return None

    try:
        slices = []
        h = hashlib.md5()
        with path.open('rb') as f:
            size_left = file_desc.file_size
            while size_left > slice_size:
                slice_data = ReadFull(f, slice_size)
                h.update(slice_data)
                slices.append(slice_data)
                size_left -= slice_size
            slice_data = ReadFull(f, size_left)
            h.update(slice_data)
            slices.append(slice_data + (b'\0' * (slice_size - len(slice_data))))
            if h.digest() != file_desc.md5:
                print(f'ERROR: file failed MD5 checksum')
                return None
        return slices

    except Exception as e:
        print(f"ERROR: couldn't read file at {path}")
        traceback.print_exception(e)  # for debugging
        return None


def ProcessResourceSetPackets(packets: dict[PacketHeader, Any], input_path: Path):

    packets_by_type: dict[bytes, dict[PacketHeader, Any]] = defaultdict(dict)
    for head, packet in packets.items():
        packets_by_type[head.ptyp][head] = packet

    for packet in packets_by_type[PAR2_PKT_TYP_CREATOR].values():
        print('Creator:', packet.creator)

    for packet in packets_by_type[PAR2_PKT_TYP_COMMASCI].values():
        print('Comment:', packet.comment)

    main_packets = packets_by_type[PAR2_PKT_TYP_MAIN].values()
    if len(main_packets) > 1:
        print('ERROR: Multiple different main packets found!', file=sys.stderr)
        return

    if len(main_packets) == 0:
        print('ERROR: Missing main packet!', file=sys.stderr)
        return

    main: MainPacket = next(iter(main_packets))

    file_descs_by_file_id: dict[bytes, FileDescPacket] = {}
    for packet in packets_by_type[PAR2_PKT_TYP_FILEDESC].values():
        if packet.file_id in file_descs_by_file_id:
            print(f'ERROR: Multiple different file descriptions found for file ID {packet.file_id.hex()}', file=sys.stderr)
        else:
            file_descs_by_file_id[packet.file_id] = packet

    ifsc_packets_by_file_id: dict[bytes, IfscPacket] = {}
    for packet in packets_by_type[PAR2_PKT_TYP_IFSC].values():
        ifsc_packets_by_file_id[packet.file_id] = packet

    input_slices: list[bytes] = []
    for file_id in main.recovery_file_ids:
        file_desc = file_descs_by_file_id.get(file_id)
        if file_desc is None:
            print(f'ERROR: Missing file description for recovery file ID {file_id.hex()}', file=sys.stderr)
        else:
            ifsc = ifsc_packets_by_file_id.get(file_id)
            if ifsc is None:
                print(f'ERROR: Missing file slice checksums for recovery file ID {file_id.hex()}', file=sys.stderr)
            else:
                slices_needed = (file_desc.file_size + main.slice_size - 1) // main.slice_size
                if slices_needed != len(ifsc.checksums):
                    print(f'ERROR: Number of checksums does not match file size (excepted: {slices_needed}, actual: {len(ifsc.checksums)})', file=sys.stderr)

                # TODO: this is the wrong way to do it. We have checksums for
                # individual slices so we should read them individually, while
                # this function is all-or-nothing (if the file is valid it returns
                # all slices, if it is not, it returns nothing)
                file_slices = ExtractInputSlices(file_desc, main.slice_size)
                if file_slices is None:
                    # Error has already been printed
                    # TODO: actually recover the data in this case!
                    return
                input_slices.extend(file_slices)
    print(f'Have {len(input_slices)} input slices')

    recv_slices_by_exponent: dict[int, bytes] = {}
    for packet in packets_by_type[PAR2_PKT_TYP_RECVSLIC].values():
        if packet.exp in recv_slices_by_exponent:
            print(f'ERROR: Multiple different recovery slices with exponent {packet.exp}', file=sys.stderr)
        elif len(packet.data) != main.slice_size:
            print(f'ERROR: Recovery slice has incorrect length (excepted: {main.slice_size}, actual {len(packet.data)}')
        else:
            recv_slices_by_exponent[packet.exp] = packet.data

    print(f'Have {len(recv_slices_by_exponent)} recovery slices')

    # Lazily import here only to avoid slow start
    import calc

    print('Verifying each recovery slice')
    for exp, data in recv_slices_by_exponent.items():
        generated = calc.GenerateRecoverySlice(exp, input_slices)
        print('Recovery slice with exponent', exp, 'OK' if generated == data else 'BAD!')
        assert data == generated

    print('Trying to recover each individual slice')
    for i in range(len(input_slices)):
        slices: list[bytes | None] = list(input_slices)
        slices[i] = None
        assert calc.Recover(slices, recv_slices_by_exponent) == [input_slices[i]]
        print(f'{i + 1}/{len(input_slices)} succeeded')

    print('Trying to recover a maximal subset')
    max_missing = min(len(recv_slices_by_exponent), len(input_slices))
    min_remain = len(input_slices) - max_missing
    for i in range(max_missing):
        from random import sample
        remaining = set(sample(range(len(input_slices)), min_remain))
        remaining_slices = [data if i in remaining else None for i, data in enumerate(input_slices)]
        missing_slices = [data for i, data in enumerate(input_slices) if i not in remaining]
        assert remaining_slices.count(None) == len(missing_slices)
        assert calc.Recover(remaining_slices, recv_slices_by_exponent) == missing_slices
        print(f'{i + 1}/{max_missing} succeeded')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage:', os.path.basename(sys.argv[0]), '<filename.par2>')
    else:
        arg = sys.argv[1]
        input_path=Path(os.path.dirname(arg))
        prefix=os.path.basename(arg).removesuffix('.par2')
        scanner = ParScanner()
        for filename in input_path.glob(prefix + '*.par2'):
            print('Processing input file', filename)
            with open(filename, 'rb') as f:
                try:
                    ReadPackets(f, scanner.HandlePacket)
                except Exception as e:
                    print(f'ERROR: error occured while reading', e)
                    traceback.print_exception(e)  # for debugging

        for (rsid, packets) in scanner.GetPacketsByRsid().items():
            print(f'Processing resource set ID {rsid.hex()}')
            ProcessResourceSetPackets(packets, input_path=input_path)

# TODO:
#   - later: need better way to issue diagnostics (include file and location etc.)
