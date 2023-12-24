use rayon::prelude::*;
use rayon::range::Iter;
use tfhe::integer::BooleanBlock;
use crate::ciphertext::{FheAsciiChar, FheString};
use crate::server_key::ServerKey;
use crate::server_key::pattern::{CharIter, IsMatch};

impl ServerKey {
    // Compare pat with str, with pat shifted right (in relation to str) the number given by iter
    fn compare_shifted(
        &self,
        str_pat: (CharIter, CharIter),
        par_iter: Iter<usize>,
        ignore_pat_pad: bool,
    ) -> BooleanBlock
    {
        let mut result = self.key.create_trivial_boolean_block(false);
        let (str, pat) = str_pat;

        let matched: Vec<_> = par_iter.map(|start| {
            let str_chars = str.clone().skip(start);
            let pat_chars = pat.clone();

            if ignore_pat_pad {
                let str_pat = str_chars.into_iter()
                    .zip(pat_chars)
                    .par_bridge();

                self.asciis_eq_ignore_pat_pad(str_pat)
            } else {
                let a: Vec<&FheAsciiChar> = str_chars.collect();
                let b: Vec<&FheAsciiChar> = pat_chars.collect();

                self.asciis_eq(a.into_iter(), b.into_iter())
            }
        }).collect();

        for match_case in matched {
            // One of the possible values of pat must match the str
            self.key.boolean_bitor_assign(&mut result, &match_case);
        }

        result
    }

    /// Returns `true` if the given encrypted pattern matches a sub-string of
    /// this encrypted string.
    ///
    /// Returns `false` if it does not.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys();
    /// let (bananas, nana, apples) = ("bananas", "nana", "apples");
    ///
    /// let enc_bananas = FheString::new(&ck, &bananas, None);
    /// let enc_nana = FheString::new(&ck, &nana, None);
    /// let enc_apples = FheString::new(&ck, &apples, None);
    ///
    /// let result1 = sk.contains(&enc_bananas, &enc_nana);
    /// let result2 = sk.contains(&enc_bananas, &enc_apples);
    ///
    /// let should_be_true = ck.key().decrypt_bool(&result1);
    /// let should_be_false = ck.key().decrypt_bool(&result2);
    ///
    /// assert!(should_be_true);
    /// assert!(!should_be_false);
    /// ```
    pub fn contains(&self, str: &FheString, pat: &FheString) -> BooleanBlock {

        match self.length_checks(str, pat) {
            IsMatch::Clear(val) => {
                return self.key.create_trivial_boolean_block(val);
            },
            IsMatch::Cipher(val) => return val,
            _ => (),
        }

        let ignore_pat_pad = pat.is_padded();

        let null = if !str.is_padded() && pat.is_padded() {
            Some(FheAsciiChar::null(self))
        } else {
            None
        };

        let (str_iter, pat_iter, iter) = self.contains_cases(str, pat, null.as_ref());

        self.compare_shifted((str_iter, pat_iter), iter.into_par_iter(), ignore_pat_pad)
    }

    /// Returns `true` if the given encrypted pattern matches a prefix of this
    /// encrypted string.
    ///
    /// Returns `false` if it does not.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys();
    /// let (bananas, ba, nan) = ("bananas", "ba", "nan");
    ///
    /// let enc_bananas = FheString::new(&ck, &bananas, None);
    /// let enc_ba = FheString::new(&ck, &ba, None);
    /// let enc_nan = FheString::new(&ck, &nan, None);
    ///
    /// let result1 = sk.starts_with(&enc_bananas, &enc_ba);
    /// let result2 = sk.starts_with(&enc_bananas, &enc_nan);
    ///
    /// let should_be_true = ck.key().decrypt_bool(&result1);
    /// let should_be_false = ck.key().decrypt_bool(&result2);
    ///
    /// assert!(should_be_true);
    /// assert!(!should_be_false);
    /// ```
    pub fn starts_with(&self, str: &FheString, pat: &FheString) -> BooleanBlock {
        let pat_len = pat.chars().len();
        let str_len = str.chars().len();

        match self.length_checks(str, pat) {
            IsMatch::Clear(val) => {
                return self.key.create_trivial_boolean_block(val);
            },
            IsMatch::Cipher(val) => return val,
            _ => (),
        }

        if !pat.is_padded() {
            let a = str.chars().iter();
            let b = pat.chars().iter();

            return self.asciis_eq(a, b)
        }

        // In the padded pattern case we can remove the last char (as it's always null)
        let pat_chars = &pat.chars()[..pat_len - 1];

        let null = FheAsciiChar::null(self);
        let str_chars = if !str.is_padded() && (str_len < pat_len - 1) {
                // If str = "xy" and pat = "xyz\0", then str[..] == pat[..2], but instead we have
                // to check if "xy\0" == pat[..3] (i.e. check that the actual pattern isn't longer)
                CharIter::Extended(str.chars().iter().chain(std::iter::once(&null)))
            } else {
                CharIter::Iter(str.chars().iter())
            };

        let str_pat = str_chars.into_iter()
            .zip(pat_chars)
            .par_bridge();

        self.asciis_eq_ignore_pat_pad(str_pat)
    }

    /// Returns `true` if the given encrypted pattern matches a suffix of this
    /// encrypted string.
    ///
    /// Returns `false` if it does not.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys();
    /// let (bananas, anas, nana) = ("bananas", "anas", "nana");
    ///
    /// let enc_bananas = FheString::new(&ck, &bananas, None);
    /// let enc_anas = FheString::new(&ck, &anas, None);
    /// let enc_nana = FheString::new(&ck, &nana, None);
    ///
    /// let result1 = sk.ends_with(&enc_bananas, &enc_anas);
    /// let result2 = sk.ends_with(&enc_bananas, &enc_nana);
    ///
    /// let should_be_true = ck.key().decrypt_bool(&result1);
    /// let should_be_false = ck.key().decrypt_bool(&result2);
    ///
    /// assert!(should_be_true);
    /// assert!(!should_be_false);
    /// ```
    pub fn ends_with(&self, str: &FheString, pat: &FheString) -> BooleanBlock {

        match self.length_checks(str, pat) {
            IsMatch::Clear(val) => {
                return self.key.create_trivial_boolean_block(val);
            },
            IsMatch::Cipher(val) => return val,
            _ => (),
        }

        let null = if str.is_padded() ^ pat.is_padded() {
            Some(FheAsciiChar::null(self))
        } else {
            None
        };

        let (str_iter, pat_iter, iter) = self.ends_with_cases(str, pat, null.as_ref());

        self.compare_shifted((str_iter, pat_iter), iter.into_par_iter(), false)
    }
}