use std::ops::Range;
use rayon::prelude::*;
use tfhe::integer::RadixCiphertext;
use crate::ciphertext::{FheAsciiChar, FheString};
use crate::server_key::pattern::IsMatch;
use crate::server_key::{CharIter, FheStringLen, ServerKey};

impl ServerKey {
    fn compare_shifted_strip(
        &self,
        strip_str: &mut FheString,
        str_pat: (CharIter, CharIter),
        iter: Range<usize>,
        ignore_pat_pad: bool,
    ) -> RadixCiphertext
    {
        let mut result = self.key.create_trivial_zero_radix(1);
        let (str, pat) = str_pat;

        let pat_len = pat.clone().count();
        let str_len = str.clone().count();
        for start in iter {

            let str_chars = str.clone().skip(start);
            let pat_chars = pat.clone();

            let mut is_matched = if ignore_pat_pad {
                let str_pat = str_chars.into_iter()
                    .zip(pat_chars)
                    .par_bridge();

                self.asciis_eq_ignore_pat_pad(str_pat)
            } else {
                let a: Vec<&FheAsciiChar> = str_chars.collect();
                let b: Vec<&FheAsciiChar> = pat_chars.collect();

                self.asciis_eq(a.into_iter(), b.into_iter())
            };

            let mut mask = self.key.extend_radix_with_trivial_zero_blocks_msb(&is_matched, 3);

            // If mask == 0u8, it will now be 255u8. If it was 1u8, it will now be 0u8
            self.key.scalar_sub_assign_parallelized(&mut mask, 1);

            let mutate_chars = if start + pat_len < str_len {
                &mut strip_str.chars_mut()[start..start + pat_len]
            } else {
                &mut strip_str.chars_mut()[start..]
            };

            rayon::join(
                || {
                    mutate_chars.par_iter_mut()
                        .for_each(|char| {
                        self.key.bitand_assign_parallelized(char.ciphertext_mut(), &mask);
                    });
                },
                // One of the possible values of pat must match the str
                || self.key.smart_bitor_assign_parallelized(&mut result, &mut is_matched),
            );
        }

        result
    }

    /// Returns an encrypted string without the given encrypted prefix and a boolean
    /// flag indicating whether the prefix was found and removed.
    ///
    /// If the encrypted string starts with the given encrypted pattern, returns the
    /// rest of the string after the pattern as an encrypted string. Otherwise,
    /// returns the original encrypted string. The boolean is `true` if the pattern
    /// was found and stripped, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys();
    /// let (s, prefix, no_match_prefix) = ("hello world", "hello", "world");
    ///
    /// let enc_s = FheString::new(&ck, &s, None);
    /// let enc_prefix = FheString::new(&ck, &prefix, None);
    /// let enc_no_match_prefix = FheString::new(&ck, &no_match_prefix, None);
    ///
    /// let (result, found) = sk.strip_prefix(&enc_s, &enc_prefix);
    /// let stripped = ck.decrypt_ascii(&result);
    /// let found = ck.key().decrypt_radix::<u8>(&found) != 0;
    ///
    /// let (result_no_match, not_found) = sk.strip_prefix(&enc_s, &enc_no_match_prefix);
    /// let not_stripped = ck.decrypt_ascii(&result_no_match);
    /// let not_found = ck.key().decrypt_radix::<u8>(&not_found) != 0;
    ///
    /// assert!(found);
    /// assert_eq!(stripped, " world"); // "hello" is stripped from "hello world"
    ///
    /// assert!(!not_found);
    /// assert_eq!(not_stripped, "hello world"); // No match, original string returned
    /// ```
    pub fn strip_prefix(&self, str: &FheString, pat: &FheString) -> (FheString, RadixCiphertext) {
        let mut result = str.clone();

        match self.length_checks(str, pat) {
            // If IsMatch is Clear we return the same string (a true means the pattern is empty)
            IsMatch::Clear(bool) => {
                return (result, self.key.create_trivial_radix(bool as u8, 1))
            },
            // If IsMatch is Cipher it means str is empty so in any case we return the same string
            IsMatch::Cipher(val) => {
                return (result, val)
            },
            _ => (),
        };

        let (starts_with, real_pat_len) = rayon::join(
            || self.starts_with(str, pat),
            || {
                match self.len(pat) {
                    FheStringLen::Padding(enc_val) => enc_val,
                    FheStringLen::NoPadding(val) => {
                        self.key.create_trivial_radix(val as u32, 16)
                    }
                }
            }
        );

        // If there's match we shift the str left by `real_pat_len` (removing the prefix and adding nulls at the end),
        // else we shift it left by 0
        let shift_left = self.key.if_then_else_parallelized(
            &starts_with,
            &real_pat_len,
            &self.key.create_trivial_zero_radix(16),
        );

        result = self.left_shift_chars(str, &shift_left);

        // If str was not padded originally we don't know if result has nulls at the end or not (we don't know if str
        // was shifted or not) so we ensure it's padded in order to be used in other functions safely
        if !str.is_padded() {
            result.append_null(self);
        } else {
            result.set_is_padded(true);
        }

        (result, starts_with)
    }

    /// Returns an encrypted string without the given encrypted suffix and a boolean
    /// flag indicating whether the suffix was found and removed.
    ///
    /// If the encrypted string ends with the given encrypted pattern, returns the
    /// rest of the string before the pattern as an encrypted string. Otherwise,
    /// returns the original encrypted string. The boolean is `true` if the pattern
    /// was found and stripped, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys();
    /// let (s, suffix, no_match_suffix) = ("hello world", "world", "hello");
    ///
    /// let enc_s = FheString::new(&ck, &s, None);
    /// let enc_suffix = FheString::new(&ck, &suffix, None);
    /// let enc_no_match_suffix = FheString::new(&ck, &no_match_suffix, None);
    ///
    /// let (result, found) = sk.strip_suffix(&enc_s, &enc_suffix);
    /// let stripped = ck.decrypt_ascii(&result);
    /// let found = ck.key().decrypt_radix::<u8>(&found) != 0;
    ///
    /// let (result_no_match, not_found) = sk.strip_suffix(&enc_s, &enc_no_match_suffix);
    /// let not_stripped = ck.decrypt_ascii(&result_no_match);
    /// let not_found = ck.key().decrypt_radix::<u8>(&not_found) != 0;
    ///
    /// assert!(found);
    /// assert_eq!(stripped, "hello "); // "world" is stripped from "hello world"
    ///
    /// assert!(!not_found);
    /// assert_eq!(not_stripped, "hello world"); // No match, original string returned
    /// ```
    pub fn strip_suffix(&self, str: &FheString, pat: &FheString) -> (FheString, RadixCiphertext) {
        let mut result = str.clone();

        match self.length_checks(str, pat) {
            // If IsMatch is Clear we return the same string (a true means the pattern is empty)
            IsMatch::Clear(bool) => {
                return (result, self.key.create_trivial_radix(bool as u8, 1))
            },
            // If IsMatch is Cipher it means str is empty so in any case we return the same string
            IsMatch::Cipher(val) => {
                return (result, val)
            },
            _ => (),
        }

        let null = if str.is_padded() ^ pat.is_padded() {
            Some(FheAsciiChar::null(self))
        } else {
            None
        };

        let (str_iter, pat_iter, iter) = self.ends_with_cases(str, pat, null.as_ref());
        let str_pat = (str_iter, pat_iter);

        let is_match = self.compare_shifted_strip(&mut result, str_pat, iter, false);

        // If str was originally non padded, the result is now potentially padded as we may have made the last chars
        // null, so we ensure it's padded in order to be used as input to other functions safely
        if !str.is_padded() {
            result.append_null(self);
        }

        (result, is_match)
    }
}