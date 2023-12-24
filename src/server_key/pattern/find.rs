use rayon::{vec::IntoIter, prelude::*};
use tfhe::integer::{BooleanBlock, RadixCiphertext};
use crate::ciphertext::{FheAsciiChar, FheString};
use crate::server_key::{CharIter, FheStringIsEmpty, FheStringLen, ServerKey};
use crate::server_key::pattern::IsMatch;

impl ServerKey {
    // Compare pat with str, with pat shifted right (in relation to str) the number of times given
    // by iter. Returns the first character index of the last match, or the first character index
    // of the first match if the range is reversed. If there's no match defaults to 0
    fn compare_shifted_index(
        &self,
        str_pat: (CharIter, CharIter),
        par_iter: IntoIter<usize>,
        ignore_pat_pad: bool,
    ) -> (RadixCiphertext, BooleanBlock)
    {
        let mut result = self.key.create_trivial_boolean_block(false);
        let mut last_match_index = self.key.create_trivial_zero_radix(16);
        let (str, pat) = str_pat;

        let matched: Vec<_> = par_iter.map(|start| {

            let str_chars = str.clone().skip(start);
            let pat_chars = pat.clone();

            let is_matched = if ignore_pat_pad {
                let str_pat = str_chars.into_iter()
                    .zip(pat_chars)
                    .par_bridge();

                self.asciis_eq_ignore_pat_pad(str_pat)
            } else {
                let a: Vec<&FheAsciiChar> = str_chars.collect();
                let b: Vec<&FheAsciiChar> = pat_chars.collect();

                self.asciis_eq(a.into_iter(), b.into_iter())
            };

            (start, is_matched)
        }).collect();

        for (i, is_matched) in matched {
            let index = self.key.create_trivial_radix(i as u32, 16);

            rayon::join(
                || {
                    last_match_index = self.key.if_then_else_parallelized(
                        &is_matched,
                        &index,
                        &last_match_index,
                    )
                },
                // One of the possible values of the padded pat must match the str
                || self.key.boolean_bitor_assign(&mut result, &is_matched),
            );
        }

        (last_match_index, result)
    }

    /// Searches for the given encrypted pattern in this encrypted string, and returns
    /// a tuple of an index and a boolean indicating the first occurrence of the pattern.
    ///
    /// The index is the position of the start of the first occurrence of the pattern,
    /// and the boolean is `true` if a match is found, and `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys();
    /// let (haystack, needle) = ("hello world", "world");
    ///
    /// let enc_haystack = FheString::new(&ck, &haystack, None);
    /// let enc_needle = FheString::new(&ck, &needle, None);
    ///
    /// let (index, found) = sk.find(&enc_haystack, &enc_needle);
    ///
    /// let index = ck.key().decrypt_radix::<u32>(&index);
    /// let found = ck.key().decrypt_bool(&found);
    ///
    /// assert!(found);
    /// assert_eq!(index, 6); // "world" starts at index 6 in "hello world"
    /// ```
    pub fn find(&self, str: &FheString, pat: &FheString) -> (RadixCiphertext, BooleanBlock) {

        match self.length_checks(str, pat) {
            IsMatch::Clear(val) => {
                // val = true if pattern is empty, in which the first match index is 0, else if
                // it's false we default to 0
                let index = self.key.create_trivial_zero_radix(16);

                return (index, self.key.create_trivial_boolean_block(val))
            },

            // This variant is only returned in the empty string case so in any case index is 0
            IsMatch::Cipher(val) => {
                return (self.key.create_trivial_zero_radix(16), val)
            },
            _ => (),
        }

        let ignore_pat_pad = pat.is_padded();

        let null = if !str.is_padded() && pat.is_padded() {
            Some(FheAsciiChar::null(self))
        } else {
            None
        };

        let (str_iter, pat_iter, iter) = self.contains_cases(str, pat, null.as_ref());

        let iter_values: Vec<_> = iter.rev().collect();

        self.compare_shifted_index((str_iter, pat_iter), iter_values.into_par_iter(), ignore_pat_pad)
    }

    /// Searches for the given encrypted pattern in this encrypted string, and returns
    /// a tuple of an index and a boolean indicating the last occurrence of the pattern.
    ///
    /// The index is the position of the start of the last occurrence of the pattern,
    /// and the boolean is `true` if a match is found, and `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys();
    /// let (haystack, needle) = ("hello world world", "world");
    ///
    /// let enc_haystack = FheString::new(&ck, &haystack, None);
    /// let enc_needle = FheString::new(&ck, &needle, None);
    ///
    /// let (index, found) = sk.rfind(&enc_haystack, &enc_needle);
    ///
    /// let index = ck.key().decrypt_radix::<u32>(&index);
    /// let found = ck.key().decrypt_bool(&found);
    ///
    /// assert!(found);
    /// assert_eq!(index, 12); // The last "world" starts at index 12 in "hello world world"
    /// ```
    pub fn rfind(&self, str: &FheString, pat: &FheString) -> (RadixCiphertext, BooleanBlock) {
        let str_len = str.chars().len();

        match self.length_checks(str, pat) {
            IsMatch::Clear(val) => {
                // val = true if pattern is empty, in which the last match index = str.len()
                let index = if val {
                    match self.len(str) {
                        FheStringLen::Padding(cipher_len) => cipher_len,
                        FheStringLen::NoPadding(len) => {
                            self.key.create_trivial_radix(len as u32, 16)
                        },
                    }
                } else {
                    // If there's no match default index is 0
                    self.key.create_trivial_zero_radix(16)
                };

                return (index, self.key.create_trivial_boolean_block(val))
            },

            // This variant is only returned in the empty string case so in any case index is 0
            IsMatch::Cipher(val) => {
                return (self.key.create_trivial_zero_radix(1), val)
            },
            _ => (),
        }

        let ignore_pat_pad = pat.is_padded();

        let (null, ext_iter) = if !str.is_padded() && pat.is_padded() {
                (Some(FheAsciiChar::null(self)), Some(0..str_len + 1))
            } else {
                (None, None)
            };

        let (str_iter, pat_iter, iter) = self.contains_cases(str, pat, null.as_ref());

        let iter_values: Vec<_> = ext_iter.unwrap_or(iter).collect();

        let ((mut last_match_index, result), option) = rayon::join(
            || {
                self.compare_shifted_index(
                    (str_iter, pat_iter),
                    iter_values.into_par_iter(),
                    ignore_pat_pad,
                )
            },
            || {
                // We have to check if pat is empty as in that case the returned index is str.len()
                // (the actual length) which doesn't correspond to our `last_match_index`
                let padded_pat_is_empty = match self.is_empty(pat) {
                    FheStringIsEmpty::Padding(is_empty) => Some(is_empty),
                    _ => None,
                };

                // The non padded str case was handled thanks to + 1 in the ext_iter
                if str.is_padded() && padded_pat_is_empty.is_some() {
                    let str_true_len = match self.len(str) {
                        FheStringLen::Padding(cipher_len) => cipher_len,
                        FheStringLen::NoPadding(len) => {
                            self.key.create_trivial_radix(len as u32, 16)
                        },
                    };

                    Some((padded_pat_is_empty.unwrap(), str_true_len))
                } else {
                    None
                }
            }
        );

        if let Some((pat_is_empty, str_true_len)) = option {
            last_match_index = self.key.if_then_else_parallelized(
                &pat_is_empty,
                &str_true_len,
                &last_match_index,
            );
        }

        (last_match_index, result)
    }
}