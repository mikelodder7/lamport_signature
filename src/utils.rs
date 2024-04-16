/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::MultiVec;

pub fn separate_one_and_zero_values(
    input: &[u8],
    bytes: usize,
) -> (MultiVec<u8, 2>, MultiVec<u8, 2>) {
    let bits = bytes * 8;
    let mut zero_values = MultiVec::fill([bits, bytes], 0);
    let mut one_values = MultiVec::fill([bits, bytes], 0);

    zero_values.data = input[..bits * bytes].to_vec();
    one_values.data = input[bits * bytes..].to_vec();
    (zero_values, one_values)
}
