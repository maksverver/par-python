from dataclasses import dataclass
import hashlib
import io
import sys
import struct
from typing import Any, Callable, IO, cast, TYPE_CHECKING
from blake3 import blake3  # optional if you don't need PAR3 support

if TYPE_CHECKING:
    Hash = hashlib._Hash
else:
    Hash = None

class Blake3:
    '''blake3 wrapper that changes the default length from 32.'''

    auto = blake3.AUTO
    block_size = blake3.block_size
    digest_size = blake3.digest_size
    key_size = blake3.key_size
    name = blake3.name

    def __init__(self, data=None, /, *, default_length=32,
            key=None, derive_key_context=None,
            max_threads: int = 1,
            usedforsecurity: bool = True
    ):
        self.state = blake3(
            data,                                               # type: ignore
            key=key, derive_key_context=derive_key_context,     # type: ignore
            max_threads=max_threads, usedforsecurity=usedforsecurity)
        self.default_length = default_length

    def copy(self):
        # Not as efficient as it could be, but ok
        res = Blake3()
        res.state = self.state.copy()
        return res

    def reset(self):
        self.state.reset()

    def update(self, data):
        self.state.update(data)

    def update_mmap(self, /, path):
        self.state.update_mmap(path)

    def digest(self, /, length=None, seek=0):
        if length is None:
            length = self.default_length
        return self.state.digest(length, seek=seek)

    def hexdigest(self, /, length=None, seek=0):
        if length is None:
            length = self.default_length
        return self.state.hexdigest(length, seek=seek)


type ByteReader = IO[bytes] | BodyReader

# Parity Volume Set Specification 2.0
# https://parchive.sourceforge.net/docs/specifications/parity-volume-spec/article-spec.html

PAR2_PKT_HEAD_MAGIC  = b'PAR2\0PKT'
PAR2_PKT_HEAD_FORMAT = '<Q16s16s16s'
PAR2_PKT_HEAD_SIZE   = len(PAR2_PKT_HEAD_MAGIC) + struct.calcsize(PAR2_PKT_HEAD_FORMAT)

# Parity Volume Set Specification 3.0
# https://parchive.github.io/doc/Parity_Volume_Set_Specification_v3.0.html#packets

PAR3_PKT_HEAD_MAGIC  = b'PAR3\0PKT'
PAR3_PKT_HEAD_FORMAT = '<16sQ8s8s'
PAR3_PKT_HEAD_SIZE   = len(PAR3_PKT_HEAD_MAGIC) + struct.calcsize(PAR3_PKT_HEAD_FORMAT)

# PAR2 and PAR3 have the same magic length and first char
PKT_MAGIC_LEN = len(PAR2_PKT_HEAD_MAGIC)
PKT_MAGIC_CHR = PAR2_PKT_HEAD_MAGIC[0]
assert PKT_MAGIC_LEN == len(PAR3_PKT_HEAD_MAGIC)
assert PKT_MAGIC_CHR == PAR3_PKT_HEAD_MAGIC[0]



# Buffer size used to read data in some places
BUFFER_SIZE = 64 << 10  # 64 KiB


@dataclass(frozen=True)
class PacketHeader:
    ver: int            # PAR version (2 or 3)
    size: int           # Size of the body (excluding header!)
    csum: bytes         # checksum (MD5 or BLAKE3) (16 bytes)
    rsid: bytes         # Resource Set ID (16 bytes)
    ptyp: bytes         # Packet Type (16 bytes)


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

    def read(self, n: int = -1) -> bytes:
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


class HashingBodyReader[H: Hash](BodyReader):
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

    def read(self, n: int = -1) -> bytes:
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


def FindMagic(f: ByteReader, warn_about_padding=True) -> int | None:
    # This relies on PAR2 and PAR3 having the same magic size and start char.
    buf = ReadFull(f, PKT_MAGIC_LEN)
    while True:
        if buf == PAR2_PKT_HEAD_MAGIC:
            return 2
        if buf == PAR3_PKT_HEAD_MAGIC:
            return 3
        if len(buf) < PKT_MAGIC_LEN:
            return None  # EOF reached

        # This could be optimized but I'm not sure it matters.
        i = buf.find(PKT_MAGIC_CHR, 1)
        if i == -1:
            i = len(buf)
        if warn_about_padding and buf[:i].count(0) != i:
            print('WARNING: nonzero padding bytes found', file=sys.stderr)
            padding_warning = False  # don't warn more than once
        buf = buf[i:]
        buf += ReadFull(f, i)


def ReadPacketHeader(f: IO[bytes]) -> PacketHeader | None:
    '''Reads the next packet header from the file, skipping padding.'''
    ver = FindMagic(f)

    if ver == 2:
        data = ReadExact(f, PAR2_PKT_HEAD_SIZE - len(PAR2_PKT_HEAD_MAGIC))
        size, csum, rsid, ptyp = struct.unpack(PAR2_PKT_HEAD_FORMAT, data)
        size -= PAR2_PKT_HEAD_SIZE
        return PacketHeader(ver=ver, size=size, csum=csum, rsid=rsid, ptyp=ptyp)

    if ver == 3:
        data = ReadExact(f, PAR3_PKT_HEAD_SIZE - len(PAR3_PKT_HEAD_MAGIC))
        csum, size, rsid, ptyp = struct.unpack(PAR3_PKT_HEAD_FORMAT, data)
        size -= PAR3_PKT_HEAD_SIZE
        return PacketHeader(ver=ver, csum=csum, size=size, rsid=rsid, ptyp=ptyp)

    assert ver is None
    return None



def Unicode(b: bytes) -> str:
    '''Converts bytes to a UTF-8 string (replacing invalid characters)'''
    return str(b, 'UTF-8', 'replace')


type PacketHandler = Callable[[PacketHeader, HashingBodyReader], Any]


def ReadPackets(file: IO[bytes], handler: PacketHandler | None):
    while (head := ReadPacketHeader(file)) is not None:
        if head.size < 0:
            print(f'WARNING: packet of type {Unicode(head.ptyp)} with length shorter than header; skipped', file=sys.stderr)
            continue

        if head.ver == 2:
            h = hashlib.md5()
            h.update(head.rsid)
            h.update(head.ptyp)
        elif head.ver == 3:
            h = cast(Hash, Blake3(default_length=16))
            h.update(struct.pack('Q', head.size + PAR3_PKT_HEAD_SIZE))
            h.update(head.rsid)
            h.update(head.ptyp)

        else:
            assert False  # unsupported version

        reader = HashingBodyReader(file, head.size, h)

        if handler is not None:
            handler(head, reader)

        csum = reader.finishhash().digest()
        if csum != head.csum:
            print(f'WARNING: packet of type {Unicode(head.ptyp)} failed checksum (expected: {head.csum.hex()} computed: {csum.hex()})')
