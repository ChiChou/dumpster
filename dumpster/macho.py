from __future__ import annotations

import struct
from dataclasses import dataclass


class MachO:
    MH_MAGIC = 0xFEEDFACE
    MH_MAGIC_64 = 0xFEEDFACF
    MH_CIGAM = 0xCEFAEDFE
    MH_CIGAM_64 = 0xCFFAEDFE

    FAT_MAGIC = 0xCAFEBABE
    FAT_CIGAM = 0xBEBAFECA

    LC_ENCRYPTION_INFO = 0x21
    LC_ENCRYPTION_INFO_64 = 0x2C

    _MAGICS = {MH_MAGIC, MH_MAGIC_64, MH_CIGAM, MH_CIGAM_64}
    _FAT = {FAT_MAGIC, FAT_CIGAM}

    @staticmethod
    def parse(data: bytes) -> MachO | None:
        if len(data) < 4:
            return None
        (magic,) = struct.unpack_from("<I", data, 0)
        if magic in MachO._FAT and len(data) >= 8:
            return FatBinary(data)
        if magic in MachO._MAGICS:
            return ThinBinary(data, 0)
        return None

    @staticmethod
    def is_macho(data: bytes) -> bool:
        if len(data) < 4:
            return False
        (magic,) = struct.unpack_from("<I", data, 0)
        return magic in MachO._MAGICS or magic in MachO._FAT

    def encryption_info(self) -> ...:
        raise NotImplementedError


@dataclass(frozen=True)
class EncryptionInfo:
    cryptoff: int
    cryptsize: int
    cryptid: int


class ThinBinary(MachO):
    def __init__(self, data: bytes, offset: int = 0) -> None:
        self.data = data
        self.offset = offset

        (magic,) = struct.unpack_from("<I", data, offset)
        if magic in (MachO.MH_MAGIC, MachO.MH_CIGAM):
            self.is64, self.swap = False, False if magic == MachO.MH_MAGIC else True
        else:
            self.is64, self.swap = True, magic == MachO.MH_CIGAM_64

        self._fmt = ">" if self.swap else "<"
        self._header_size = 32 if self.is64 else 28
        self.ncmds, _ = struct.unpack_from(self._fmt + "II", data, offset + 16)

    def encryption_info(self) -> list[EncryptionInfo]:
        results: list[EncryptionInfo] = []
        lc_offset = self.offset + self._header_size
        for _ in range(self.ncmds):
            if lc_offset + 8 > len(self.data):
                break
            cmd, cmdsize = struct.unpack_from(self._fmt + "II", self.data, lc_offset)
            if cmd in (MachO.LC_ENCRYPTION_INFO, MachO.LC_ENCRYPTION_INFO_64):
                fmt = "<III" if not self.swap else ">III"
                cryptoff, cryptsize, cryptid = struct.unpack_from(
                    fmt, self.data, lc_offset + 8
                )
                results.append(
                    EncryptionInfo(cryptoff=cryptoff, cryptsize=cryptsize, cryptid=cryptid)
                )
            lc_offset += cmdsize
        return results


class FatBinary(MachO):
    def __init__(self, data: bytes) -> None:
        self.data = data
        (magic,) = struct.unpack_from("<I", data, 0)
        self.swap = magic == MachO.FAT_CIGAM
        fmt = "<" if not self.swap else ">"
        (self.nfat,) = struct.unpack_from(fmt + "I", data, 4)
        self._fmt = fmt

    def slices(self) -> list[ThinBinary]:
        result: list[ThinBinary] = []
        for i in range(self.nfat):
            fa_offset = 8 + i * 20
            if fa_offset + 20 > len(self.data):
                break
            _, _, arch_offset, _, _ = struct.unpack_from(
                self._fmt + "IIIII", self.data, fa_offset
            )
            # enough data for at least a Mach-O header read
            if arch_offset + 24 > len(self.data):
                continue
            result.append(ThinBinary(self.data, arch_offset))
        return result

    def encryption_info(self) -> list[EncryptionInfo]:
        results: list[EncryptionInfo] = []
        for s in self.slices():
            results.extend(s.encryption_info())
        return results
