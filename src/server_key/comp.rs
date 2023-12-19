use rayon::prelude::ParallelBridge;
use tfhe::integer::RadixCiphertext;
use crate::ciphertext::{FheAsciiChar, FheString};
use crate::server_key::{CharIter, FheStringIsEmpty, ServerKey};

impl ServerKey {
    fn eq_length_checks(&self, lhs: &FheString, rhs: &FheString) -> Option<RadixCiphertext> {
        let lhs_len = lhs.chars().len();
        let rhs_len = rhs.chars().len();

        // If lhs is empty, rhs must also be empty in order to be equal (the case where lhs is
        // empty with > 1 padding zeros is handled next)
        if lhs_len == 0 || (lhs.is_padded() && lhs_len == 1) {
            return match self.is_empty(rhs) {
                FheStringIsEmpty::Padding(enc_val) => Some(enc_val),
                FheStringIsEmpty::NoPadding(val) => {
                    Some(self.key.create_trivial_radix(val as u8, 1))
                }
            }
        }

        // If rhs is empty, lhs must also be empty in order to be equal (only case remaining is if
        // lhs padding zeros > 1)
        if rhs_len == 0 || (rhs.is_padded() && rhs_len == 1) {
            return match self.is_empty(lhs) {
                FheStringIsEmpty::Padding(enc_val) => Some(enc_val),
                _ => Some(self.key.create_trivial_zero_radix(1)),
            }
        }

        // Two strings without padding that have different lengths cannot be equal
        if (!lhs.is_padded() && !rhs.is_padded()) && (lhs.chars().len() != rhs.chars().len()) {
            return Some(self.key.create_trivial_zero_radix(1));
        }

        // A string without padding cannot be equal to a string with padding that has the same or
        // lower length
        if (!lhs.is_padded() && rhs.is_padded()) && (rhs.chars().len() <= lhs.chars().len()) ||
            (!rhs.is_padded() && lhs.is_padded()) && (lhs.chars().len() <= rhs.chars().len())
        {
            return Some(self.key.create_trivial_zero_radix(1));
        }

        None
    }

    /// Returns `true` if two encrypted strings are exactly equal.
    ///
    /// Returns `false` if they are not equal.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys();
    /// let (s1, s2) = ("hello", "hello");
    ///
    /// let enc_s1 = FheString::new(&ck, &s1, None);
    /// let enc_s2 = FheString::new(&ck, &s2, None);
    ///
    /// let result = sk.eq(&enc_s1, &enc_s2);
    /// let are_equal = ck.key().decrypt_radix::<u8>(&result) != 0;
    ///
    /// assert!(are_equal);
    /// ```
    pub fn eq(&self, lhs: &FheString, rhs: &FheString) -> RadixCiphertext {
        if let Some(val) = self.eq_length_checks(lhs, rhs) { return val }

        let lhs_len = lhs.chars().len();
        let rhs_len = rhs.chars().len();

        // We have to append a null to the non padded part such that "xx" != "xxx\0"
        let null = if (!lhs.is_padded() && lhs_len < rhs_len - 1) ||
            (!rhs.is_padded() && rhs_len < lhs_len - 1) {
            Some(FheAsciiChar::null(self))
        } else {
            None
        };

        let lhs_chars = if !lhs.is_padded() && lhs_len < rhs_len - 1 {
            let chars = lhs.chars().iter()
                .chain(std::iter::once(null.as_ref().unwrap()));

            CharIter::Extended(chars)
        } else {
            CharIter::Iter(lhs.chars().iter())
        };

        let rhs_chars = if !rhs.is_padded() && rhs_len < lhs_len - 1 {
            let chars = rhs.chars().iter()
                .chain(std::iter::once(null.as_ref().unwrap()));

            CharIter::Extended(chars)
        } else {
            CharIter::Iter(rhs.chars().iter())
        };

        let lhs_rhs = lhs_chars.into_iter()
            .zip(rhs_chars)
            .par_bridge();

        self.asciis_eq(lhs_rhs)
    }

    /// Returns `true` if two encrypted strings are not equal.
    ///
    /// Returns `false` if they are equal.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys();
    /// let (s1, s2) = ("hello", "world");
    ///
    /// let enc_s1 = FheString::new(&ck, &s1, None);
    /// let enc_s2 = FheString::new(&ck, &s2, None);
    ///
    /// let result = sk.ne(&enc_s1, &enc_s2);
    /// let are_not_equal = ck.key().decrypt_radix::<u8>(&result) != 0;
    ///
    /// assert!(are_not_equal);
    /// ```
    pub fn ne(&self, lhs: &FheString, rhs: &FheString) -> RadixCiphertext {
        let eq = self.eq(lhs, rhs);

        // 01 XOR 01 = 00, 00 XOR 01 = 01
        self.key.scalar_bitxor_parallelized(&eq, 1u8)
    }

    /// Returns `true` if the first encrypted string is less than the second encrypted string.
    ///
    /// Returns `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys();
    /// let (s1, s2) = ("apple", "banana");
    ///
    /// let enc_s1 = FheString::new(&ck, &s1, None);
    /// let enc_s2 = FheString::new(&ck, &s2, None);
    ///
    /// let result = sk.lt(&enc_s1, &enc_s2);
    /// let is_lt = ck.key().decrypt_radix::<u8>(&result) != 0;
    ///
    /// assert!(is_lt); // "apple" is less than "banana"
    /// ```
    pub fn lt(&self, lhs: &FheString, rhs: &FheString) -> RadixCiphertext {
        let mut lhs_uint = lhs.to_uint(self);
        let mut rhs_uint = rhs.to_uint(self);

        self.pad_ciphertexts_lsb(&mut lhs_uint, &mut rhs_uint);

        self.key.lt_parallelized(&lhs_uint, &rhs_uint)
    }

    /// Returns `true` if the first encrypted string is greater than the second encrypted string.
    ///
    /// Returns `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys();
    /// let (s1, s2) = ("banana", "apple");
    ///
    /// let enc_s1 = FheString::new(&ck, &s1, None);
    /// let enc_s2 = FheString::new(&ck, &s2, None);
    ///
    /// let result = sk.gt(&enc_s1, &enc_s2);
    /// let is_gt = ck.key().decrypt_radix::<u8>(&result) != 0;
    ///
    /// assert!(is_gt); // "banana" is greater than "apple"
    /// ```
    pub fn gt(&self, lhs: &FheString, rhs: &FheString) -> RadixCiphertext {
        let mut lhs_uint = lhs.to_uint(self);
        let mut rhs_uint = rhs.to_uint(self);

        self.pad_ciphertexts_lsb(&mut lhs_uint, &mut rhs_uint);

        self.key.gt_parallelized(&lhs_uint, &rhs_uint)
    }

    /// Returns `true` if the first encrypted string is less than or equal to the second encrypted string.
    ///
    /// Returns `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys();
    /// let (s1, s2) = ("apple", "banana");
    ///
    /// let enc_s1 = FheString::new(&ck, &s1, None);
    /// let enc_s2 = FheString::new(&ck, &s2, None);
    ///
    /// let result = sk.le(&enc_s1, &enc_s2);
    /// let is_le = ck.key().decrypt_radix::<u8>(&result) != 0;
    ///
    /// assert!(is_le); // "apple" is less than or equal to "banana"
    /// ```
    pub fn le(&self, lhs: &FheString, rhs: &FheString) -> RadixCiphertext {
        let mut lhs_uint = lhs.to_uint(self);
        let mut rhs_uint = rhs.to_uint(self);

        self.pad_ciphertexts_lsb(&mut lhs_uint, &mut rhs_uint);

        self.key.le_parallelized(&lhs_uint, &rhs_uint)
    }

    /// Returns `true` if the first encrypted string is greater than or equal to the second encrypted string.
    ///
    /// Returns `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys();
    /// let (s1, s2) = ("banana", "apple");
    ///
    /// let enc_s1 = FheString::new(&ck, &s1, None);
    /// let enc_s2 = FheString::new(&ck, &s2, None);
    ///
    /// let result = sk.ge(&enc_s1, &enc_s2);
    /// let is_ge = ck.key().decrypt_radix::<u8>(&result) != 0;
    ///
    /// assert!(is_ge); // "banana" is greater than or equal to "apple"
    /// ```
    pub fn ge(&self, lhs: &FheString, rhs: &FheString) -> RadixCiphertext {
        let mut lhs_uint = lhs.to_uint(self);
        let mut rhs_uint = rhs.to_uint(self);

        self.pad_ciphertexts_lsb(&mut lhs_uint, &mut rhs_uint);

        self.key.ge_parallelized(&lhs_uint, &rhs_uint)
    }
}