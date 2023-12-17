mod split_iters;

use tfhe::integer::RadixCiphertext;
use crate::ciphertext::{FheString, UIntArg};
use crate::server_key::{FheStringIsEmpty, FheStringIterator, FheStringLen, ServerKey};
use crate::server_key::pattern::IsMatch;

impl ServerKey {
    fn split_pat_at_index(
        &self,
        str: &FheString,
        pat: &FheString,
        index: &RadixCiphertext,
        inclusive: bool,
    ) -> (FheString, FheString) {
        let str_len = self.key.create_trivial_radix(str.chars().len() as u32, 16);
        let real_pat_len = match self.len(pat) {
            FheStringLen::Padding(enc_val) => enc_val,
            FheStringLen::NoPadding(val) => {
                self.key.create_trivial_radix(val as u32, 16)
            }
        };

        let mut shift_right = self.key.sub_parallelized(&str_len, index);
        if inclusive {
            // Remove the real pattern length from the amount to shift
            self.key.sub_assign_parallelized(&mut shift_right, &real_pat_len);
        }

        let shift_left = self.key.add_parallelized(&real_pat_len, index);

        let mut lhs = self.right_shift_chars(str, &shift_right);
        // lhs potentially has nulls in the leftmost chars as we have shifted str right, so we move back the nulls to
        // the end by performing the reverse shift
        lhs = self.left_shift_chars(&lhs, &shift_right);

        let mut rhs = self.left_shift_chars(str, &shift_left);

        // If original str is padded we set both sub strings padded as well. If str was not padded, then we don't know
        // if a sub string is padded or not, so we add a null to both because we cannot assume one isn't padded
        if str.is_padded() {
            lhs.set_is_padded(true);
            rhs.set_is_padded(true);
        } else {
            lhs.append_null(self);
            rhs.append_null(self);
        }

        (lhs, rhs)
    }

    pub fn rsplit_once(&self, str: &FheString, pat: &FheString) -> (FheString, FheString, RadixCiphertext) {
        match self.length_checks(str, pat) {
            IsMatch::Clear(val) => {
                return if val {
                    // `val` is set only when the pattern is empty, so the last match is at the end
                    (str.clone(), FheString::empty(), self.key.create_trivial_radix(1, 1))
                } else {
                    // There's no match so we default to empty string and str
                    (FheString::empty(), str.clone(), self.key.create_trivial_radix(0, 1))
                }
            }
            // This is only returned when str is empty so both sub-strings are empty as well
            IsMatch::Cipher(enc_val) => {
                return (FheString::empty(), FheString::empty(), enc_val)
            }
            _ => (),
        }

        let (index, is_match) = self.rfind(str, pat);

        let (lhs, rhs) = self.split_pat_at_index(str, pat, &index, false);

        (lhs, rhs, is_match)
    }

    pub fn split_once(&self, str: &FheString, pat: &FheString) -> (FheString, FheString, RadixCiphertext) {
        match self.length_checks(str, pat) {
            IsMatch::Clear(val) => {
                return if val {
                    // `val` is set only when the pattern is empty, so the first match is index 0
                    (FheString::empty(), str.clone(), self.key.create_trivial_radix(1, 1))
                } else {
                    // There's no match so we default to empty string and str
                    (FheString::empty(), str.clone(), self.key.create_trivial_radix(0, 1))
                }
            }
            // This is only returned when str is empty so both sub-strings are empty as well
            IsMatch::Cipher(enc_val) => {
                return (FheString::empty(), FheString::empty(), enc_val)
            }
            _ => (),
        }

        let (index, is_match) = self.find(str, pat);

        let (lhs, rhs) = self.split_pat_at_index(str, pat, &index, false);

        (lhs, rhs, is_match)
    }

    fn split_internal(&self, str: &FheString, pat: &FheString, split_type: SplitType) -> SplitInternal {
        let mut max_counter = match self.len(str) {
            FheStringLen::Padding(enc_val) => enc_val,
            FheStringLen::NoPadding(val) => {
                self.key.create_trivial_radix(val as u32, 16)
            }
        };

        self.key.scalar_add_assign_parallelized(&mut max_counter, 1);

        SplitInternal {
            split_type,
            state: str.clone(),
            pat: pat.clone(),
            prev_was_some: self.key.create_trivial_radix(1, 1),
            counter: 0,
            max_counter,
            counter_lt_max: self.key.create_trivial_radix(1, 1),
        }
    }

    fn splitn_internal(&self, str: &FheString, pat: &FheString, n: UIntArg, split_type: SplitType) -> SplitNInternal {
        if let SplitType::SplitInclusive = split_type { panic!("We have either SplitN or RSplitN") }

        let uint_not_0 = match &n {
            UIntArg::Clear(val) => {
                if *val != 0 {
                    self.key.create_trivial_radix(1, 1)
                } else {
                    self.key.create_trivial_zero_radix(1)
                }
            }
            UIntArg::Enc(enc) => {
                self.key.scalar_ne_parallelized(enc.cipher(), 0)
            }
        };

        let internal = self.split_internal(str, pat, split_type);

        SplitNInternal {
            internal,
            n,
            counter: 0,
            not_exceeded: uint_not_0,
        }
    }

    fn split_no_trailing(&self, str: &FheString, pat: &FheString, split_type: SplitType) -> SplitNoTrailing {
        if let SplitType::RSplit = split_type { panic!("Only Split or SplitInclusive") }

        let max_counter = match self.len(str) {
            FheStringLen::Padding(enc_val) => enc_val,
            FheStringLen::NoPadding(val) => {
                self.key.create_trivial_radix(val as u32, 16)
            }
        };

        let internal = SplitInternal {
            split_type,
            state: str.clone(),
            pat: pat.clone(),
            prev_was_some: self.key.create_trivial_radix(1, 1),
            counter: 0,
            max_counter,
            counter_lt_max: self.key.create_trivial_radix(1, 1),
        };

        SplitNoTrailing { internal }
    }

    fn split_no_leading(&self, str: &FheString, pat: &FheString) -> SplitNoLeading {
        let mut internal = self.split_internal(str, pat, SplitType::RSplit);

        let prev_return = internal.next(self);

        let leading_empty_str = match self.is_empty(&prev_return.0) {
            FheStringIsEmpty::Padding(enc) => enc,
            FheStringIsEmpty::NoPadding(clear) => self.key.create_trivial_radix(clear as u32, 1),
        };

        SplitNoLeading {
            internal,
            prev_return,
            leading_empty_str,
        }
    }
}

enum SplitType {
    Split,
    RSplit,
    SplitInclusive,
}

struct SplitInternal {
    split_type: SplitType,
    state: FheString,
    pat: FheString,
    prev_was_some: RadixCiphertext,
    counter: u16,
    max_counter: RadixCiphertext,
    counter_lt_max: RadixCiphertext,
}

struct SplitNInternal {
    internal: SplitInternal,
    n: UIntArg,
    counter: u16,
    not_exceeded: RadixCiphertext,
}

struct SplitNoTrailing {
    internal: SplitInternal,
}

struct SplitNoLeading {
    internal: SplitInternal,
    prev_return: (FheString, RadixCiphertext),
    leading_empty_str: RadixCiphertext,
}

impl FheStringIterator for SplitInternal {
    fn next(&mut self, sk: &ServerKey) -> (FheString, RadixCiphertext) {

        let (mut index, mut is_some) = if let SplitType::RSplit = self.split_type {
            sk.rfind(&self.state, &self.pat)
        } else {
            sk.find(&self.state, &self.pat)
        };

        let pat_is_empty = match sk.is_empty(&self.pat) {
            FheStringIsEmpty::Padding(mut enc) => {
                sk.key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut enc, 15);
                enc
            },
            FheStringIsEmpty::NoPadding(clear) => {
                sk.key.create_trivial_radix(clear as u32, 16)
            },
        };

        if self.counter > 0 {
            // If pattern is empty and we aren't in the first next call, we add (in the Split case)
            // or subtract (in the RSplit case) 1 to the index at which we split the str.
            //
            // This is because "ab".split("") returns ["", "a", "b", ""] and, in our case, we have
            // to manually advance the match index as an empty pattern always matches at the very
            // start (or end in the rsplit case)

            if let SplitType::RSplit = self.split_type {
                sk.key.sub_assign_parallelized(&mut index, &pat_is_empty);
            } else {
                sk.key.add_assign_parallelized(&mut index, &pat_is_empty);
            }
        }

        let (lhs, rhs) = if let SplitType::SplitInclusive = self.split_type {
            sk.split_pat_at_index(&self.state, &self.pat, &index, true)
        } else {
            sk.split_pat_at_index(&self.state, &self.pat, &index, false)
        };

        let current_is_some = is_some.clone();

        // The moment it's None (no match) we return the remaining state
        let result = if let SplitType::RSplit = self.split_type {
            let re = sk.conditional_string(&current_is_some, rhs, &self.state);

            self.state = lhs;
            re
        } else {
            let re = sk.conditional_string(&current_is_some, lhs, &self.state);

            self.state = rhs;
            re
        };

        // Even if there isn't match, we return Some if there was match in the previous next call,
        // as we are returning the remaining state "wrapped" in Some
        sk.key.bitor_assign_parallelized(&mut is_some, &self.prev_was_some);

        // If pattern is empty, `is_some` is always true, so we make it false when we have reached
        // the last possible counter value
        sk.key.bitand_assign_parallelized(&mut is_some, &self.counter_lt_max);

        self.prev_was_some = current_is_some;
        self.counter_lt_max = sk.key.scalar_gt_parallelized(&self.max_counter, self.counter);
        self.counter += 1;

        (result, is_some)
    }
}

impl FheStringIterator for SplitNInternal {
    fn next(&mut self, sk: &ServerKey) -> (FheString, RadixCiphertext) {
        let state = self.internal.state.clone();

        let (mut result, mut is_some) = self.internal.next(sk);

        // This keeps the original `is_some` value unless we have exceeded n
        sk.key.bitand_assign_parallelized(&mut is_some, &self.not_exceeded);

        // The moment counter is at least one less than n we return the remaining state, and make
        // `not_exceeded` false such that next calls are always None
        match &self.n {
            UIntArg::Clear(clear_n) => {
                if self.counter >= clear_n - 1 {

                    result = state;
                    self.not_exceeded = sk.key.create_trivial_zero_radix(1);
                }
            }
            UIntArg::Enc(enc_n) => {
                // Note that when `enc_n` is zero `n_minus_one` wraps to a very large number and so `exceeded` will be
                // false. Nonetheless the initial value of `not_exceeded` was set to false in the n is zero case, so
                // we return None
                let n_minus_one = sk.key.scalar_sub_parallelized(enc_n.cipher(), 1);
                let exceeded = sk.key.scalar_le_parallelized(&n_minus_one, self.counter);

                result = sk.conditional_string(&exceeded, state, &result);

                let false_ct = sk.key.create_trivial_zero_radix(1);
                self.not_exceeded = sk.key.if_then_else_parallelized(&exceeded, &false_ct, &self.not_exceeded);
            }
        }

        self.counter += 1;

        (result, is_some)
    }
}

impl FheStringIterator for SplitNoTrailing {
    fn next(&mut self, sk: &ServerKey) -> (FheString, RadixCiphertext) {
        let (result, mut is_some) = self.internal.next(sk);

        // It's possible that the returned value is Some but it's wrapping the remaining state (if
        // prev_was_some is false). If this is the case and we have a trailing empty string, we
        // return None to remove it
        let result_is_empty = match sk.is_empty(&result) {
            FheStringIsEmpty::Padding(enc) => enc,
            FheStringIsEmpty::NoPadding(clear) => sk.key.create_trivial_radix(clear as u32, 1),
        };

        // Invert the bit value (01 XOR 01 = 00 and 00 XOR 01 = 01)
        let prev_was_none = sk.key.scalar_bitxor_parallelized(&self.internal.prev_was_some, 1u8);
        let trailing_empty_str = sk.key.bitand_parallelized(&result_is_empty, &prev_was_none);

        is_some = sk.key.if_then_else_parallelized(
            &trailing_empty_str,
            &sk.key.create_trivial_zero_radix(1),
            &is_some,
        );

        (result, is_some)
    }
}

impl FheStringIterator for SplitNoLeading {
    fn next(&mut self, sk: &ServerKey) -> (FheString, RadixCiphertext) {
        // We want to remove the leading empty string i.e. the first returned substring should be skipped if empty.
        //
        // To achieve that we have computed a next call in advance and conditionally assign values based on the
        // `trailing_empty_str` flag

        let (result, is_some) = self.internal.next(sk);

        let return_result = sk.conditional_string(
            &self.leading_empty_str,
            result.clone(),
            &self.prev_return.0,
        );
        let return_is_some = sk.key.if_then_else_parallelized(
            &self.leading_empty_str,
            &is_some,
            &self.prev_return.1,
        );

        self.prev_return = (result, is_some);

        (return_result, return_is_some)
    }
}