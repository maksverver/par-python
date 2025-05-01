import codecs
from collections import defaultdict
from dataclasses import dataclass
import glob
import hashlib
import io
from pathlib import Path
import os
import sys
import struct
import traceback
from typing import Any, ByteString, Callable, IO


type ByteReader = IO[bytes] | BodyReader


# Parity Volume Set Specification 2.0
# https://parchive.sourceforge.net/docs/specifications/parity-volume-spec/article-spec.html

PAR2_PKT_HEAD_MAGIC  = b'PAR2\0PKT'
PAR2_PKT_HEAD_FORMAT = '<Q16s16s16s'
PAR2_PKT_HEAD_SIZE   = len(PAR2_PKT_HEAD_MAGIC) + struct.calcsize(PAR2_PKT_HEAD_FORMAT)

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


# Buffer size used to read data in some places
BUFFER_SIZE = 64 << 10  # 64 KiB


class UnexpectedEndOfFileException(Exception):
    pass


class BodyReader(io.IOBase):
    '''File wrapper that allows only a fixed-sized portion of the underlying
    file to be read. Used to read packet bodies which have a known length.'''

    def __init__(self, file: IO[bytes], size_left: int):
        self.file = file
        self.size_left = size_left

    def readable(self) -> bool:
        return True

    def readall(self):
        parts = [self.read(self.size_left)]
        while self.size_left > 0:
            parts.append(self.read(self.size_left))
        return b''.join(parts)

    def read(self, n) -> bytes:
        '''Reads up to `n` bytes, or all bytes remaining if n < 0.
        May return fewer bytes than requested. Returns an empty bytestring
        only if the end of the body is reached.
        
        If the underlying file object returns an empty bytestring before the
        end of the body is reached, raises UnexpectedEndOfFileException.'''

        if self.size_left == 0:
            return b''

        if n < 0:
            return self.readall()

        res = self.file.read(min(n, self.size_left))
        if not res:
            raise UnexpectedEndOfFileException()

        assert 0 < len(res) <= self.size_left
        self.size_left -= len(res)

        return res


class HashingBodyReader[H: hashlib._Hash](BodyReader):
    '''File wrapper that also updates the hash with data read.
    Used to hash packet bodies.'''

    def __init__(self, file: IO[bytes], size_left: int, hash_start: H):
        super().__init__(file, size_left)
        self.hash = hash_start

    def finishhash(self) -> H:
        '''Reads the remaining data in the body (if any) and returns the
        final hash value.'''
        while self.size_left > 0:
            self.read(BUFFER_SIZE)
        return self.hash

    def read(self, n: int) -> bytes:
        res = super().read(n)
        self.hash.update(res)
        return res


def ReadFull(f: ByteReader, n: int) -> bytes:
    '''Reads `n` bytes from `f`, calling `f.read()` repeatedly if necessary.
       Returns a short bytestring only if end-of-file is reached.'''
    res = f.read(n)
    while len(res) < n:
        tmp = f.read(n - len(res))
        if not tmp:
            break
        res += tmp
    return res


def ReadExact(f: ByteReader, n: int) -> bytes:
    'Reads exactly `n` bytes from `f`, or raises UnexpectedEndOfFileException.'
    res = ReadFull(f, n)
    if len(res) < n:
        raise UnexpectedEndOfFileException()
    return res


def ReadStruct(f: ByteReader, format: str):
    return struct.unpack(format, ReadExact(f, struct.calcsize(format)))


def FindMagic(f: ByteReader, magic: bytes) -> bool:
    buf = ReadFull(f, len(magic))
    padding_warning = False
    while buf != magic:
        if len(buf) < len(magic):
            return False  # EOF reached

        # This could be optimized but I'm not sure it matters. 
        i = buf.find(magic[0], 1)
        if i == -1:
            i = len(buf)
        if not padding_warning and buf[:i].count(0) != i:
            print('WARNING: nonzero padding bytes found', file=sys.stderr)
            padding_warning = True  # don't warn more than once
        buf = buf[i:]
        buf += ReadFull(f, len(magic) - len(buf))
    return True

@dataclass(frozen=True)
class PacketHeader:
    size: int           # Total size of the packet (including header)
    md5: bytes          # MD5 hash code (starting from rsid) (16 bytes)
    rsid: bytes         # Resource Set ID (16 bytes)
    ptyp: bytes         # Packet Type (16 bytes)

def ReadPacketHeader(f: IO[bytes]) -> PacketHeader | None:
    '''Reads the next packet header from the file, skipping padding.'''
    if not FindMagic(f, PAR2_PKT_HEAD_MAGIC):
        return None

    data = ReadExact(f, PAR2_PKT_HEAD_SIZE - len(PAR2_PKT_HEAD_MAGIC))
    size, md5, rsid, ptyp = struct.unpack(PAR2_PKT_HEAD_FORMAT, data)
    return PacketHeader(size=size, md5=md5, rsid=rsid, ptyp=ptyp)


def Unicode(b: bytes) -> str:
    '''Converts bytes to a UTF-8 string (replacing invalid characters)'''
    return str(b, 'UTF-8', 'replace')


type PacketHandler = Callable[[PacketHeader, HashingBodyReader], Any]


def ReadPackets(file: IO[bytes], handler: PacketHandler | None):
    while (head := ReadPacketHeader(file)) is not None:
        body_size = head.size - PAR2_PKT_HEAD_SIZE
        if body_size < 0:
            print(f'WARNING: packet of type {Unicode(head.ptyp)} with length shorter than header; skipped', file=sys.stderr)
            continue

        h = hashlib.md5()
        h.update(head.rsid)
        h.update(head.ptyp)
        reader = HashingBodyReader(file, body_size, h)

        if handler is not None:
            handler(head, reader)

        md5 = reader.finishhash().digest()
        if md5 != head.md5:
            print(f'WARNING: packet of type {Unicode(head.ptyp)} has MD5 mismatch (expected: {head.md5.hex()} computed: {md5.hex()})')


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
        md5 = r.finishhash().digest()
        if md5 != head.md5:
            print(f'WARNING: packet of type {Unicode(head.ptyp)} has MD5 mismatch (expected: {head.md5.hex()} computed: {md5.hex()})')
            return

        # All good! Keep it.
        packets[head] = packet

    def HandleMain(self, head: PacketHeader, r: BodyReader) -> MainPacket | None:
        slice_size, file_count = ReadStruct(r, '<QI')
        rest = r.readall()
        if len(rest) < 16*file_count or len(rest) % 16 != 0:
            print('ERROR: main packet invalid', file=sys.stderr)
            return
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
        return

    if file_size != file_desc.file_size:
        print(f'ERROR: invalid file size of {path} (expected: {file_desc.file_size}, actual: {file_size})', file=sys.stderr)
        return

    if not path.exists():
        print(f'WARNING: File does not exist: {path}', file=sys.stderr)
        return

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
        return


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

    input_slices = []
    for file_id in main.recovery_file_ids:
        file_desc = file_descs_by_file_id.get(file_id)
        if file_desc is None:
            print(f'ERROR: Missing file description for recovery file ID {file_id}', file=sys.stderr)
        else:
            ifsc = ifsc_packets_by_file_id.get(file_id)
            if ifsc is None:
                print(f'ERROR: Missing file slice checksums for recovery file ID {file_id}', file=sys.stderr)
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

        # Verify recovery slice is correct
        assert calc.GenerateRecoverySlice(exp, input_slices) == data

    print('Trying to recover each individual slice')
    for i in range(len(input_slices)):
        slices = list(input_slices)
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
    input_path=Path('test')
    prefix='file'
    scanner = ParScanner()
    for filename in input_path.glob(prefix + '*par2'):
        print('Processing input file', filename)
        with open(filename, 'rb') as f:
            try:
                ReadPackets(f, scanner.HandlePacket)
            except Exception as e:
                print(f'ERROR: error occured while reading', e)
                traceback.print_exception(e)  # for debugging

    for (rsid, packets) in scanner.GetPacketsByRsid().items():
        print(f'Processing resource set ID {rsid}')
        ProcessResourceSetPackets(packets, input_path=input_path)

# TODO:
#   - later: need better way to issue diagnostics (include file and location etc.)
