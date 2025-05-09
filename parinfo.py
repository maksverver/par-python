#!/usr/bin/env python3

from collections import defaultdict
from dataclasses import dataclass
from parser import (
    ReadPackets, PacketHeader, HashingBodyReader,
    PAR2_PKT_HEAD_SIZE, PAR3_PKT_HEAD_SIZE,
)
import sys

@dataclass
class PacketSummary:
    total_count: int
    unique_count: int
    total_head_size: int
    total_body_size: int


@dataclass
class Summary:
    filesize: int
    padding: int
    packets: PacketSummary
    packets_by_type: dict[bytes, PacketSummary]


def GetHeaderSize(header: PacketHeader) -> int:
    if header.ver == 2:
        return PAR2_PKT_HEAD_SIZE
    if header.ver == 3:
        return PAR3_PKT_HEAD_SIZE
    raise ValueError(f'Unknown packet version {header.ver}')


def GetTotalSize(header: PacketHeader) -> int:
    return header.size + GetHeaderSize(header)


class PacketSummarizer:
    def __init__(self):
        self.total_count = 0
        self.unique_count = 0
        self.total_head_size = 0
        self.total_body_size = 0

        self.seen = set()

    def HandlePacket(self, header: PacketHeader):
        self.total_count += 1

        if header not in self.seen:
            self.seen.add(header)
            self.unique_count += 1

        self.total_head_size += GetHeaderSize(header)
        self.total_body_size += header.size

    def GetSummary(self):
        return PacketSummary(
            total_count=self.total_count,
            unique_count=self.unique_count,
            total_head_size=self.total_head_size,
            total_body_size=self.total_body_size,
        )


class Summarizer:
    def __init__(self):
        self.payload_size = 0  # both headers and bodies
        self.packets = PacketSummarizer()
        self.by_type = defaultdict(PacketSummarizer)

    def HandlePacket(self, header: PacketHeader):
        self.payload_size += GetTotalSize(header)
        self.packets.HandlePacket(header)
        self.by_type[header.ptyp].HandlePacket(header)

    def GetSummary(self, filesize: int) -> Summary:
        return Summary(
            filesize=filesize,
            padding=filesize - self.payload_size,
            packets=self.packets.GetSummary(),
            packets_by_type={ptyp: psum.GetSummary() for ptyp, psum in self.by_type.items()}
        )


def PrintSummary(summary: Summary, file=sys.stdout):
    print(f'  Total packet count: {summary.packets.total_count:16,d}', file=file)
    print(f'    of which unique:  {summary.packets.unique_count:16,d}', file=file)
    print(f'  File size (bytes):  {summary.filesize:16,d}', file=file)
    print(f'    of which headers: {summary.packets.total_head_size:16,d}', file=file)
    print(f'    of which bodies:  {summary.packets.total_body_size:16,d}', file=file)
    print(f'    of which padding: {summary.padding:16,d}', file=file)
    print(file=file)
    if (summary.packets_by_type):
        print('  Packets by type:', file=file)
        for ptyp, psum in summary.packets_by_type.items():
            print(file=file)
            psize = psum.total_head_size + psum.total_body_size
            uniq_size      = psize * psum.unique_count // psum.total_count
            uniq_head_size = psum.total_head_size * psum.unique_count // psum.total_count
            uniq_body_size = psum.total_body_size * psum.unique_count // psum.total_count
            print(f'  {repr(ptyp.rstrip(b'\0'))[2:-1]}', file=file)
            print(f'    Packet count:            {psum.total_count:16,d}', file=file)
            print(f'      of which unique:       {psum.unique_count:16,d}', file=file)
            print(f'    Total size (no padding): {psize:16,d}', file=file)
            print(f'      of which headers:      {psum.total_head_size:16,d}', file=file)
            print(f'      of which bodies:       {psum.total_body_size:16,d}', file=file)
            print(f'    Unique size:             {uniq_size:16,d}', file=file)
            print(f'      of which headers:      {uniq_head_size:16,d}', file=file)
            print(f'      of which bodies:       {uniq_body_size:16,d}', file=file)
        print(file=file)


def ProcessFiles(filenames: list[str], file=sys.stdout):
    total_filesize = 0
    global_summarizer = Summarizer()
    for filename in sys.argv[1:]:
        local_summarizer = Summarizer()

        def ProcessFile(filename: str):
            def HandlePacket(header: PacketHeader, reader: HashingBodyReader):
                local_summarizer.HandlePacket(header)
                global_summarizer.HandlePacket(header)

            nonlocal total_filesize
            with open(filename, 'rb') as f:
                ReadPackets(f, HandlePacket)
                filesize = f.tell()
                total_filesize += filesize

                print(f'Summary for file {filename}:', file=file)
                print(file=file)
                PrintSummary(local_summarizer.GetSummary(filesize), file=file)

        ProcessFile(filename)

    print('SUMMARY ACROSS ALL FILES', file=file)
    print(file=file)
    PrintSummary(global_summarizer.GetSummary(total_filesize), file=file)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Prints info about the packets contained in par2 files')
        print()
        print(f'Usage: {sys.argv[0]} <file...>')
        sys.exit(1)

    ProcessFiles(sys.argv[1:], file=sys.stderr)
