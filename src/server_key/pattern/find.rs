use tfhe::integer::RadixCiphertext;
use crate::ciphertext::{FheAsciiChar, FheString};
use crate::server_key::{FheStringIsEmpty, FheStringLen, ServerKey};
use crate::server_key::pattern::IsMatch;

impl ServerKey {
    // Compare pat with str, with pat shifted right (in relation to str) the number of times given
    // by iter. Returns the first character index of the last match, or the first character index
    // of the first match if the range is reversed. If there's no match defaults to 0
    fn compare_shifted_index<'a, I, U, V>(
        &self,
        str_pat: (U, V),
        iter: I,
        ignore_pat_pad: bool,
    ) -> (RadixCiphertext, RadixCiphertext)
        where I: Iterator<Item = usize>,
              U: Iterator<Item = &'a FheAsciiChar> + Clone,
              V: Iterator<Item = &'a FheAsciiChar> + Clone,
    {
        let mut result = self.key.create_trivial_zero_radix(1);
        let mut last_match_index = self.key.create_trivial_zero_radix(16);
        let (str, pat) = str_pat;

        for start in iter {

            let str_chars = str.clone().skip(start);
            let pat_chars = pat.clone();

            let mut is_matched = if ignore_pat_pad {
                self.asciis_eq_ignore_pat_pad(str_chars, pat_chars)
            } else {
                self.asciis_eq(str_chars, pat_chars)
            };

            let index = self.key.create_trivial_radix(start as u32, 16);
            last_match_index = self.key.if_then_else_parallelized(
                &is_matched,
                &index,
                &last_match_index,
            );

            // One of the possible values of the padded pat must match the str
            self.key.smart_bitor_assign_parallelized(&mut result, &mut is_matched);
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
    /// let found = ck.key().decrypt_radix::<u8>(&found) != 0;
    ///
    /// assert!(found);
    /// assert_eq!(index, 6); // "world" starts at index 6 in "hello world"
    /// ```
    pub fn find(&self, str: &FheString, pat: &FheString) -> (RadixCiphertext, RadixCiphertext) {

        match self.length_checks(str, pat) {
            IsMatch::Clear(val) => {
                // val = true if pattern is empty, in which the first match index is 0, else if
                // it's false we default to 0
                let index = self.key.create_trivial_zero_radix(16);

                return (index, self.key.create_trivial_radix(val as u8, 1))
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

        self.compare_shifted_index((str_iter, pat_iter), iter.rev(), ignore_pat_pad)
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
    /// let found = ck.key().decrypt_radix::<u8>(&found) != 0;
    ///
    /// assert!(found);
    /// assert_eq!(index, 12); // The last "world" starts at index 12 in "hello world world"
    /// ```
    pub fn rfind(&self, str: &FheString, pat: &FheString) -> (RadixCiphertext, RadixCiphertext) {
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

                return (index, self.key.create_trivial_radix(val as u8, 1))
            },

            // This variant is only returned in the empty string case so in any case index is 0
            IsMatch::Cipher(val) => {
                return (self.key.create_trivial_zero_radix(1), val)
            },
            _ => (),
        }

        let ignore_pat_pad = pat.is_padded();

        let (null, ext_iter): (_, Option<Box<dyn DoubleEndedIterator<Item=usize>>>) =
            if !str.is_padded() && pat.is_padded() {
                (
                    Some(FheAsciiChar::null(self)),
                    Some(Box::new(0..str_len + 1)),
                )
            } else {
                (None, None)
            };

        let (str_iter, pat_iter, iter) = self.contains_cases(str, pat, null.as_ref());

        let (mut last_match_index, result) = self.compare_shifted_index(
            (str_iter, pat_iter),
            ext_iter.unwrap_or(iter),
            ignore_pat_pad,
        );

        // The non padded str case is handled thanks to + 1 in the ext_iter
        if str.is_padded() && pat.is_padded() {
            // We have to check if pat is empty as in that case the returned index is str.len()
            // (the actual length) which doesn't correspond to our `last_match_index`
            if let FheStringIsEmpty::Padding(is_empty) = self.is_empty(pat) {
                let str_true_len = match self.len(str) {
                    FheStringLen::Padding(cipher_len) => cipher_len,
                    FheStringLen::NoPadding(len) => {
                        self.key.create_trivial_radix(len as u32, 16)
                    },
                };

                last_match_index = self.key.if_then_else_parallelized(
                    &is_empty,
                    &str_true_len,
                    &last_match_index,
                );
            }
        }

        (last_match_index, result)
    }
}