mod no_patterns;
mod trim;
mod pattern;
mod comp;

use std::cmp::Ordering;
use tfhe::integer::{IntegerCiphertext, RadixCiphertext, ServerKey as FheServerKey};
use crate::ciphertext::{FheAsciiChar, FheString};
use crate::client_key::ClientKey;

/// Represents a server key to operate homomorphically on [`FheString`].
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ServerKey {
    key: FheServerKey,
}

pub fn gen_keys() -> (ClientKey, ServerKey) {
    let ck = ClientKey::new();
    let sk = ServerKey::new(&ck);

    (ck, sk)
}

impl ServerKey {
    pub fn new(from: &ClientKey) -> Self {
        Self { key: FheServerKey::new(from.key()) }
    }

    pub fn key(&self) -> &FheServerKey {
        &self.key
    }

    pub fn trivial_encrypt_ascii(&self, str: &str) -> TrivialEncryptOutput {
        assert!(str.is_ascii() & !str.contains('\0'));

        let enc_chars: Vec<_> = str.bytes()
            .map(|char| self.key.create_trivial_radix(char, 4))
            .collect();

        TrivialEncryptOutput { output: enc_chars }
    }
}

pub struct TrivialEncryptOutput {
    output: Vec<RadixCiphertext>,
}

impl TrivialEncryptOutput {
    pub fn value(self) -> Vec<RadixCiphertext> {
        self.output
    }
}

// With no padding, the length is just the vector's length (clear result). With padding it requires
// homomorphically counting the non zero elements (encrypted result).
pub enum FheStringLen {
    NoPadding(usize),
    Padding(RadixCiphertext),
}

pub enum FheStringIsEmpty {
    NoPadding(bool),
    Padding(RadixCiphertext),
}

// A few helper functions for the implementations
impl ServerKey {

    // If an iterator is longer than the other, the "excess" characters are ignored
    fn asciis_eq<'a, I , J>(
        &self,
        str_chars: I,
        pat_chars: J,
    ) -> RadixCiphertext
        where
            I: IntoIterator<Item = &'a FheAsciiChar>,
            J: IntoIterator<Item = &'a FheAsciiChar>,
    {
        let mut or = self.key.create_trivial_zero_radix(4);

        for (str_char, pat_char) in str_chars.into_iter().zip(pat_chars) {
            // This will be 0u8 if both chars are equal, non-zero otherwise
            let mut xored = self.key.bitxor_parallelized(
                str_char.ciphertext(),
                pat_char.ciphertext(),
            );

            self.key.smart_bitor_assign_parallelized(&mut or, &mut xored);
        }

        // This will only be true if all characters were equal, as all the XORs would be 0u8
        let result = self.key.smart_scalar_eq_parallelized(&mut or, 0u8);

        // Return just the block containing the boolean value
        self.key.trim_radix_blocks_msb(&result, 3)
    }

    fn asciis_eq_ignore_pat_pad<'a, I , J>(
        &self,
        str_chars: I,
        pat_chars: J,
    ) -> RadixCiphertext
        where
            I: IntoIterator<Item = &'a FheAsciiChar>,
            J: IntoIterator<Item = &'a FheAsciiChar>,
    {
        let mut result = self.key.create_trivial_radix(1, 1);

        for (str_char, pat_char) in str_chars.into_iter().zip(pat_chars) {
            let mut are_eq = self.key.eq_parallelized(
                str_char.ciphertext(),
                pat_char.ciphertext(),
            );

            let mut is_null = self.key.scalar_eq_parallelized(pat_char.ciphertext(), 0u8);

            // If `pat_char` is null then `are_eq` is set to true. Hence if ALL `pat_char`s are
            // null, the result is always true, which is correct since the pattern is empty
            self.key.smart_bitor_assign_parallelized(&mut are_eq, &mut is_null);

            // Will be false if `str_char` != `pat_char` and `pat_char` isn't null
            self.key.smart_bitand_assign_parallelized(&mut result, &mut are_eq);
        }

        result
    }

    fn pad_ciphertexts_lsb(&self, lhs: &mut RadixCiphertext, rhs: &mut RadixCiphertext) {
        let lhs_blocks = lhs.blocks().len();
        let rhs_blocks = rhs.blocks().len();

        match lhs_blocks.cmp(&rhs_blocks) {
            Ordering::Less => {
                let diff = rhs_blocks - lhs_blocks;
                self.key.extend_radix_with_trivial_zero_blocks_lsb_assign(lhs, diff);
            },
            Ordering::Greater => {
                let diff = lhs_blocks - rhs_blocks;
                self.key.extend_radix_with_trivial_zero_blocks_lsb_assign(rhs, diff);
            },
            _ => (),
        }
    }

    fn pad_or_trim_ciphertext(&self, cipher: &mut RadixCiphertext, len: usize) {
        let cipher_len = cipher.blocks().len();

        match cipher_len.cmp(&len) {
            Ordering::Less => {
                let diff = len - cipher_len;
                self.key.extend_radix_with_trivial_zero_blocks_msb_assign(cipher, diff);
            },
            Ordering::Greater => {
                let diff = cipher_len - len;
                self.key.trim_radix_blocks_msb_assign(cipher, diff);
            },
            _ => (),
        }
    }

    fn conditional_string(&self, condition: &RadixCiphertext, true_ct: FheString, false_ct: &FheString) -> FheString {
        let padded = true_ct.is_padded() && false_ct.is_padded();
        let potentially_padded = true_ct.is_padded() || false_ct.is_padded();

        let mut true_ct_uint = true_ct.into_uint(self);
        let mut false_ct_uint = false_ct.to_uint(self);

        self.pad_ciphertexts_lsb(&mut true_ct_uint, &mut false_ct_uint);

        let result_uint = self.key.if_then_else_parallelized(
            condition,
            &true_ct_uint,
            &false_ct_uint,
        );

        let mut result = FheString::from_uint(result_uint);
        if padded {
            result.set_is_padded(true);

        } else if potentially_padded {
            // If the result is potentially padded we cannot assume it's not padded. We ensure that
            // result is padded with a single null that is ignored by our implementations
            result.append_null(self);
        }

        result
    }

    fn left_shift_chars(&self, str: &FheString, shift: &RadixCiphertext) -> FheString {
        let uint = str.to_uint(self);
        let mut shift_bits = self.key.scalar_left_shift_parallelized(shift, 3);

        // `shift_bits` needs to have the same block len as `uint` for the tfhe-rs shift to work
        self.pad_or_trim_ciphertext(&mut shift_bits, uint.blocks().len());

        let shifted = self.key.left_shift_parallelized(&uint, &shift_bits);

        // If the shifting amount is >= than the str length we get zero i.e. all chars are out of
        // range (instead of wrapping, which is the behavior of Rust and tfhe-rs)
        let bit_len = (str.chars().len() * 8) as u32;
        let shift_ge_than_str = self.key.scalar_ge_parallelized(&shift_bits, bit_len);

        let result = self.key.if_then_else_parallelized(
            &shift_ge_than_str,
            &self.key.create_trivial_zero_radix(uint.blocks().len()),
            &shifted,
        );

        FheString::from_uint(result)
    }

    fn right_shift_chars(&self, str: &FheString, shift: &RadixCiphertext) -> FheString {
        let uint = str.to_uint(self);
        let mut shift_bits = self.key.scalar_left_shift_parallelized(shift, 3);

        // `shift_bits` needs to have the same block len as `uint` for the tfhe-rs shift to work
        self.pad_or_trim_ciphertext(&mut shift_bits, uint.blocks().len());

        let shifted = self.key.right_shift_parallelized(&uint, &shift_bits);

        // If the shifting amount is >= than the str length we get zero i.e. all chars are out of
        // range (instead of wrapping, which is the behavior of Rust and tfhe-rs)
        let bit_len = (str.chars().len() * 8) as u32;
        let shift_ge_than_str = self.key.scalar_ge_parallelized(&shift_bits, bit_len);

        let result = self.key.if_then_else_parallelized(
            &shift_ge_than_str,
            &self.key.create_trivial_zero_radix(uint.blocks().len()),
            &shifted,
        );

        FheString::from_uint(result)
    }
}

pub trait FheStringIterator {
    fn next (&mut self, sk: &ServerKey) -> (FheString, RadixCiphertext);
}

#[derive(Clone)]
enum CharIter<'a> {
    Iter(std::slice::Iter<'a, FheAsciiChar>),
    Extended(std::iter::Chain<std::slice::Iter<'a, FheAsciiChar>, std::iter::Once<&'a FheAsciiChar>>),
}

impl<'a> Iterator for CharIter<'a> {
    type Item = &'a FheAsciiChar;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            CharIter::Iter(iter) => iter.next(),
            CharIter::Extended(iter) => iter.next(),
        }
    }
}