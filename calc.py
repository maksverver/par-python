from galois import FieldArray, GF as GaloisField
import numpy as np
import numpy.linalg
from typing import cast
from numpy.typing import NDArray

class RecoveryException(Exception):
    pass

# Based on:
# https://parchive.sourceforge.net/docs/specifications/parity-volume-spec/article-spec.html
#
# The algorithm for computing recovery slices is based on James S. Plank's tech
# report at U. of Tennessee entitled A tutorial on Reed-Solomon coding for
# fault-tolerance in RAID-like systems. The input slices are ordered and
# assigned 16-bit constants. Recovery slices are assigned 16-bit exponents.
# Each 2-byte word of the recovery slice is the sum of the contributions from
# each input slice. The contribution of each input slice is the 2-byte word of
# the input slice multiplied by the input slice's constant raised to the
# recovery slice's exponent. All these computations (adds, multiplys, powers)
# are done using the 16-bit Galois Field operations.
#
# To generate the recovery data, the slices of the input files are assigned
# constants. This is based on the order the File IDs appear in the main packet
# and then by the order the slices appear in the file. So the first slice of the
# first file in the main packet is assigned the first constant. The second slice
# of the first file is assigned the second constant. And so on. If the last
# slice of the first file has the Nth constant, the first slice of the second
# file is assigned the (N+1)th. And so on.
#
# Here, the PAR 2.0 Spec diverges from Plank's paper. In Plank, the first 
# constant is 1, the second 2, the third 3, etc. This is a bad approach because
# some constants have an order less than 65535. (That is, there exists constants
# N where N raised to a power less than 65535 is equal to 1 in the Galois
# Field.) These constants can prevent recovery matrices from being invertible
# and can, therefore, stop recovery. This spec does not use those constants. So,
# the first constant is the first power of two that has order 65535. The second
# constant is the next power of two that has order 65535. And so on. A power of
# two has order 65535 if the exponent is not equal to 0 modulus 3, 5, 17, or
# 257. In C code, that would be (n%3 != 0 && n%5 != 0 && n%17 != 0 && n%257 !=
# 0). Note - this is the exponent being tested, and not the constant itself.
# There are 32768 valid constants. The first few are:
# 2, 4, 16, 128, 256, 2048, 8192, 16384, 4107, 32856, 17132 ...
#

GF = GaloisField(2**16, irreducible_poly=0x1100B)

input_slice_constants = GF(2)**np.array([i for i in range(65536) if i % 3 and i % 5 and i % 17 and i % 257])
assert len(input_slice_constants) == 32768


def DecodeSlice(data: bytes) -> NDArray[np.uint16]:
    return np.frombuffer(data, dtype='<u2')


def EncodeSlice(vector: NDArray[np.uint16]) -> bytes:
    return np.ascontiguousarray(vector, dtype='<u2').tobytes()


def GenerateRecoverySlice(exponent: int, input_slices: list[bytes]) -> bytes:
    '''Generates a recovery slice from the given input slices.

    The exponent is an integer between 0 and 65536 (exclusive).
    Input slices must have the same length, which is a multiple of 2.
    The generated recovery slice will have the same length.
    '''

    if len(input_slices) > len(input_slice_constants):
        raise ValueError(f'Too many input slices ({len(input_slices)}; max: {len(input_slice_constants)})')

    input_rows = GF(np.array([DecodeSlice(s) for s in input_slices]), copy=False)
    multipliers = input_slice_constants[:len(input_slices)] ** exponent
    recovery_vector = np.dot(input_rows.transpose(), multipliers)
    return EncodeSlice(recovery_vector)


def Recover(input_slices: list[bytes | None], recovery_slices: dict[int, bytes]) -> list[bytes]:
    if len(input_slices) > len(input_slice_constants):
        raise ValueError(f'Too many input slices ({len(input_slices)}; max: {len(input_slice_constants)})')

    # If there are no bad input slices, no recovery is necessary
    if all(data is not None for data in input_slices):
        return cast(list[bytes], input_slices)

    # Let:
    #   n be the number of good input slices
    #   m be the number of bad input slices (=the number of recovery slices used)
    #   s be the slice length

    # Separate input slices into good and bad.
    good_rows      = GF([DecodeSlice(data) for data in input_slices if data is not None])  # n x s
    good_constants = GF([input_slice_constants[i] for i, data in enumerate(input_slices) if data is not None])  # n
    bad_constants  = GF([input_slice_constants[i] for i, data in enumerate(input_slices) if data is None])  # m

    if len(bad_constants) > len(recovery_slices):
        raise RecoveryException(f'Number of bad input slices ({len(bad_constants)}) exceeds number of recovery slices ({len(recovery_slices)})')

    # Only use the minimum amount of recovery slices needed
    recovery_slices_used = list(recovery_slices.items())[:len(bad_constants)]  # m

    recovery_rows = GF(np.array([DecodeSlice(data) for exp, data in recovery_slices_used]), copy=False)  # m x s
    recovery_exps = np.array([exp for exp, data in recovery_slices_used])   # m

    good_matrix = np.power(good_constants[np.newaxis, :], recovery_exps[:, np.newaxis])  # m x n

    recovery_rows -= good_matrix @ good_rows  # m x s

    bad_matrix = np.power(bad_constants[np.newaxis, :], recovery_exps[:, np.newaxis])  # m x m
    # raises LinAlgError if matrix is not invertible (which should not happen!)
    return [EncodeSlice(row) for row in numpy.linalg.inv(bad_matrix) @ recovery_rows]


def BasicTests():
    slice1 = b'\1\2\3\4\5\6'
    slice2 = b'\7\x08\x09\x0a\x0b\x0c'
    slice3 = b'\x0d\x0e\x0f\0\1\2'

    recovery_slices = {
        2: GenerateRecoverySlice(2, [slice1, slice2, slice3]),
        3: GenerateRecoverySlice(3, [slice1, slice2, slice3])
    }

    # Try to recover:
    assert Recover([slice1, slice2, None  ], recovery_slices) == [slice3]
    assert Recover([slice1, None,   slice3], recovery_slices) == [slice2]
    assert Recover([None,   slice2, slice3], recovery_slices) == [slice1]
    assert Recover([slice1, None,   None  ], recovery_slices) == [slice2, slice3]
    assert Recover([None,   slice2, None  ], recovery_slices) == [slice1, slice3]
    assert Recover([None,   None,   slice3], recovery_slices) == [slice1, slice2]
    try:
        Recover([None,   None,   None  ], recovery_slices)
    except RecoveryException as e:
        assert str(e) == 'Number of bad input slices (3) exceeds number of recovery slices (2)'


if __name__ == '__main__':
    BasicTests()
