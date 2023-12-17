use rayon::prelude::*;
use tfhe::integer::{IntegerCiphertext, RadixCiphertext};
use crate::ciphertext::{FheAsciiChar, FheString};
use crate::server_key::{FheStringLen, ServerKey};

pub struct SplitAsciiWhitespace {
    initial_string: FheString,
    current_mask: Option<FheString>,
}

impl SplitAsciiWhitespace {
    pub fn next(&mut self, sk: &ServerKey) -> FheString {
        let is_not_first_call = self.current_mask.is_some();

        if is_not_first_call {
            self.remaining_string(sk);
        }

        self.initial_string = sk.trim_start(&self.initial_string);

        self.create_mask(sk)
    }
}

impl SplitAsciiWhitespace {
    // The mask contains 255u8 until we find some whitespace, then will be 0u8
    fn create_mask(&mut self, sk: &ServerKey) -> FheString {
        let mut mask = self.initial_string.clone();
        let mut result = self.initial_string.clone();

        let mut prev_was_not = sk.key.create_trivial_radix(1, 1);
        for char in mask.chars_mut().iter_mut() {

            let mut is_not_ws = sk.is_not_whitespace(char);
            sk.key.bitand_assign_parallelized(&mut is_not_ws, &prev_was_not);

            let mut mask_u8 = sk.key.extend_radix_with_trivial_zero_blocks_msb(&is_not_ws, 3);

            assert_eq!(mask_u8.blocks().len(), 4);

            // 0u8 is kept the same, but 1u8 is transformed into 255u8
            sk.key.scalar_sub_assign_parallelized(&mut mask_u8, 1);
            sk.key.bitnot_assign_parallelized(&mut mask_u8);

            *char.ciphertext_mut() = mask_u8;

            prev_was_not = is_not_ws;
        }

        // Apply the mask to get the result
        result.chars_mut()
            .iter_mut()
            .zip(mask.chars())
            .par_bridge()
            .for_each(|(char, mask_u8)| {

            sk.key.bitand_assign_parallelized(
                char.ciphertext_mut(),
                mask_u8.ciphertext(),
            );
        });

        self.current_mask = Some(mask);

        result
    }

    // Shifts the string left to get the remaining string (starting at the next first whitespace)
    fn remaining_string(&mut self, sk: &ServerKey) {
        let mask = self.current_mask.as_ref().unwrap();

        let mut number_of_trues = sk.key.create_trivial_zero_radix(16);
        for mask_u8 in mask.chars() {

            let is_true = sk.key.scalar_eq_parallelized(mask_u8.ciphertext(), 255u8);
            sk.key.add_assign_parallelized(&mut number_of_trues, &is_true);
        }

        let padded = self.initial_string.is_padded();

        self.initial_string = sk.left_shift_chars(&self.initial_string, &number_of_trues);

        if padded {
            self.initial_string.set_is_padded(true);
        } else {
            println!("str was not padded so we add a null");
            // If it was not padded now we cannot assume it's not padded (because of the left shift) so we add a null
            // to ensure it's always padded
            self.initial_string.append_null(sk);
        }
    }
}

impl ServerKey {
    // As specified in https://doc.rust-lang.org/core/primitive.char.html#method.is_ascii_whitespace
    fn is_whitespace(&self, char: &FheAsciiChar, or_null: bool) -> RadixCiphertext {

        let (((is_space, is_tab), (is_new_line, is_form_feed)), is_carriage_return) = rayon::join(
            || rayon::join(
                || rayon::join(
                    || self.key.scalar_eq_parallelized(char.ciphertext(), 0x20u8),
                    || self.key.scalar_eq_parallelized(char.ciphertext(), 0x09u8),
                ),
                || rayon::join(
                    || self.key.scalar_eq_parallelized(char.ciphertext(), 0x0Au8),
                    || self.key.scalar_eq_parallelized(char.ciphertext(), 0x0Cu8),
                ),
            ),
            || self.key.scalar_eq_parallelized(char.ciphertext(), 0x0Du8),
        );

        let mut is_whitespace = self.key.bitor_parallelized(&is_space, &is_tab);
        self.key.bitor_assign_parallelized(&mut is_whitespace, &is_new_line);
        self.key.bitor_assign_parallelized(&mut is_whitespace, &is_form_feed);
        self.key.bitor_assign_parallelized(&mut is_whitespace, &is_carriage_return);

        if or_null {
            let is_null = self.key.scalar_eq_parallelized(char.ciphertext(), 0u8);

            self.key.bitor_assign_parallelized(&mut is_whitespace, &is_null);
        }

        assert_eq!(is_whitespace.blocks().len(), 4);

        // Return just the block containing the boolean value
        self.key.trim_radix_blocks_msb(&is_whitespace, 3)
    }

    fn is_not_whitespace(&self, char: &FheAsciiChar) -> RadixCiphertext {
        let result = self.is_whitespace(char, false);

        // 01 XOR 01 = 00, 00 XOR 01 = 01
        self.key.scalar_bitxor_parallelized(&result, 1u8)
    }

    fn compare_and_trim<'a, I>(&self, strip_str: I, starts_with_null: bool)
        where I: Iterator<Item = &'a mut FheAsciiChar>
    {

        let mut prev_was_ws = self.key.create_trivial_radix(1, 1);
        for char in strip_str {

            let mut is_whitespace = self.is_whitespace(char, starts_with_null);
            self.key.bitand_assign_parallelized(&mut is_whitespace, &prev_was_ws);

            *char.ciphertext_mut() = self.key.if_then_else_parallelized(
                &is_whitespace,
                &self.key.create_trivial_zero_radix(4),
                char.ciphertext(),
            );

            // Once one char isn't (leading / trailing) whitespace, next ones won't be either
            prev_was_ws = is_whitespace;
        }
    }

    /// Returns a new encrypted string with whitespace removed from the start.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys();
    /// let s = "  hello world";
    ///
    /// let enc_s = FheString::new(&ck, &s, None);
    ///
    /// let result = sk.trim_start(&enc_s);
    /// let trimmed = ck.decrypt_ascii(&result);
    ///
    /// assert_eq!(trimmed, "hello world"); // Whitespace at the start is removed
    /// ```
    pub fn trim_start(&self, str: &FheString) -> FheString {
        let mut result = str.clone();

        self.compare_and_trim(result.chars_mut().iter_mut(), false);

        // Result has potential nulls in the leftmost chars, so we compute the length difference before and after the
        // trimming, and use that amount to shift the result left. This makes the result nulls be at the end
        result.set_is_padded(true);
        if let FheStringLen::Padding(len_after_trim) = self.len(&result) {

            let original_str_len = match self.len(str) {
                FheStringLen::Padding(enc_val) => enc_val,
                FheStringLen::NoPadding(val) => {
                    self.key.create_trivial_radix(val as u32, 16)
                }
            };

            let shift_left = self.key.sub_parallelized(&original_str_len, &len_after_trim);

            result = self.left_shift_chars(&result, &shift_left);
        }

        // If str was not padded originally we don't know if result has nulls at the end or not (we don't know if str
        // was shifted or not) so we ensure it's padded in order to be used in other functions safely
        if !str.is_padded() {
            result.append_null(self);
        } else {
            result.set_is_padded(true);
        }

        result
    }

    /// Returns a new encrypted string with whitespace removed from the end.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys();
    /// let s = "hello world  ";
    ///
    /// let enc_s = FheString::new(&ck, &s, None);
    ///
    /// let result = sk.trim_end(&enc_s);
    /// let trimmed = ck.decrypt_ascii(&result);
    ///
    /// assert_eq!(trimmed, "hello world"); // Whitespace at the end is removed
    /// ```
    pub fn trim_end(&self, str: &FheString) -> FheString {
        let mut result = str.clone();

        // If str is padded, when we check for whitespace from the left we have to ignore the nulls
        let include_null = str.is_padded();

        self.compare_and_trim(result.chars_mut().iter_mut().rev(), include_null);

        // If str was originally non padded, the result is now potentially padded as we may have made the last chars
        // null, so we ensure it's padded in order to be used as input to other functions safely
        if !str.is_padded() {
            result.append_null(self);
        }

        result
    }

    /// Returns a new encrypted string with whitespace removed from both the start and end.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys();
    /// let s = "  hello world  ";
    ///
    /// let enc_s = FheString::new(&ck, &s, None);
    ///
    /// let result = sk.trim(&enc_s);
    /// let trimmed = ck.decrypt_ascii(&result);
    ///
    /// assert_eq!(trimmed, "hello world"); // Whitespace at both ends is removed
    /// ```
    pub fn trim(&self, str: &FheString) -> FheString {
        let mut result = self.trim_start(str);

        result = self.trim_end(&result);

        result
    }

    pub fn split_ascii_whitespace(&self, str: &FheString) -> SplitAsciiWhitespace {
        let result = str.clone();

        SplitAsciiWhitespace {
            initial_string: result,
            current_mask: None,
        }
    }
}