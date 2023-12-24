#[cfg(test)]
mod test_vectors;

use super::*;

impl Keys {
    pub fn assert_len(&self, str: &str, str_pad: Option<u32>) {
        let expected = str.len();

        let enc_str = FheString::new(&self.ck, str, str_pad);

        let start = Instant::now();
        let result = self.sk.len(&enc_str);
        let end = Instant::now();

        let dec = match result {
            FheStringLen::NoPadding(clear_len) => clear_len,
            FheStringLen::Padding(enc_len) => self.ck.key().decrypt_radix::<u32>(&enc_len) as usize,
        };

        println!(
            "\n\x1b[1;37;1mLen:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, expected, dec, end.duration_since(start)
        );

        assert_eq!(dec, expected);
    }

    pub fn assert_is_empty(&self, str: &str, str_pad: Option<u32>) {
        let expected = str.is_empty();

        let enc_str = FheString::new(&self.ck, str, str_pad);

        let start = Instant::now();
        let result = self.sk.is_empty(&enc_str);
        let end = Instant::now();

        let dec = match result {
            FheStringIsEmpty::NoPadding(clear_len) => clear_len,
            FheStringIsEmpty::Padding(enc_len) => self.ck.key().decrypt_bool(&enc_len),
        };

        println!(
            "\n\x1b[1;37;1mIs_empty:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, expected, dec, end.duration_since(start)
        );

        assert_eq!(dec, expected);
    }

    pub fn assert_contains(&self, str: &str, str_pad: Option<u32>, pat: &str, pat_pad: Option<u32>) {
        let expected = str.contains(pat);

        let enc_str = FheString::new(&self.ck, str, str_pad);
        let enc_pat = FheString::new(&self.ck, pat, pat_pad);

        let start = Instant::now();
        let result = self.sk.contains(&enc_str, &enc_pat);
        let end = Instant::now();

        let dec = self.ck.key().decrypt_bool(&result);

        println!(
            "\n\x1b[1;37;1mContains:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mPattern: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, pat, expected, dec, end.duration_since(start)
        );

        assert_eq!(dec, expected);
    }

    pub fn assert_ends_with(&self, str: &str, str_pad: Option<u32>, pat: &str, pat_pad: Option<u32>) {
        let expected = str.ends_with(pat);

        let enc_str = FheString::new(&self.ck, str, str_pad);
        let enc_pat = FheString::new(&self.ck, pat, pat_pad);

        let start = Instant::now();
        let result = self.sk.ends_with(&enc_str, &enc_pat);
        let end = Instant::now();

        let dec = self.ck.key().decrypt_bool(&result);

        println!(
            "\n\x1b[1;37;1mEnds_with:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mPattern: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, pat, expected, dec, end.duration_since(start)
        );

        assert_eq!(dec, expected);
    }

    pub fn assert_starts_with(&self, str: &str, str_pad: Option<u32>, pat: &str, pat_pad: Option<u32>) {
        let expected = str.starts_with(pat);

        let enc_str = FheString::new(&self.ck, str, str_pad);
        let enc_pat = FheString::new(&self.ck, pat, pat_pad);

        let start = Instant::now();
        let result = self.sk.starts_with(&enc_str, &enc_pat);
        let end = Instant::now();

        let dec = self.ck.key().decrypt_bool(&result);

        println!(
            "\n\x1b[1;37;1mStarts_with:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mPattern: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, pat, expected, dec, end.duration_since(start)
        );

        assert_eq!(dec, expected);
    }

    pub fn assert_find(&self, str: &str, str_pad: Option<u32>, pat: &str, pat_pad: Option<u32>) {
        let expected = str.find(pat);

        let enc_str = FheString::new(&self.ck, str, str_pad);
        let enc_pat = FheString::new(&self.ck, pat, pat_pad);

        let start = Instant::now();
        let (index, is_some) = self.sk.find(&enc_str, &enc_pat);
        let end = Instant::now();

        let dec_index = self.ck.key().decrypt_radix::<u32>(&index);
        let dec_is_some = self.ck.key().decrypt_bool(&is_some);

        let dec = if dec_is_some { Some(dec_index as usize) } else { None };

        println!(
            "\n\x1b[1;37;1mFind:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mPattern: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, pat, expected, dec, end.duration_since(start)
        );

        assert_eq!(dec, expected);
    }

    pub fn assert_rfind(&self, str: &str, str_pad: Option<u32>, pat: &str, pat_pad: Option<u32>) {
        let expected = str.rfind(pat);

        let enc_str = FheString::new(&self.ck, str, str_pad);
        let enc_pat = FheString::new(&self.ck, pat, pat_pad);

        let start = Instant::now();
        let (index, is_some) = self.sk.rfind(&enc_str, &enc_pat);
        let end = Instant::now();

        let dec_index = self.ck.key().decrypt_radix::<u32>(&index);
        let dec_is_some = self.ck.key().decrypt_bool(&is_some);

        let dec = if dec_is_some { Some(dec_index as usize) } else { None };

        println!(
            "\n\x1b[1;37;1mRfind:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mPattern: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, pat, expected, dec, end.duration_since(start)
        );

        assert_eq!(dec, expected);
    }

    pub fn assert_strip_prefix(&self, str: &str, str_pad: Option<u32>, pat: &str, pat_pad: Option<u32>) {
        let expected = str.strip_prefix(pat);

        let enc_str = FheString::new(&self.ck, str, str_pad);
        let enc_pat = FheString::new(&self.ck, pat, pat_pad);

        let start = Instant::now();
        let (result, is_some) = self.sk.strip_prefix(&enc_str, &enc_pat);
        let end = Instant::now();

        let dec_result = self.ck.decrypt_ascii(&result);
        let dec_is_some = self.ck.key().decrypt_bool(&is_some);

        let dec = if dec_is_some { Some(dec_result.as_str()) } else { None };

        println!(
            "\n\x1b[1;37;1mStrip_prefix:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mPattern: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, pat, expected, dec, end.duration_since(start)
        );

        assert_eq!(dec, expected);
    }

    pub fn assert_strip_suffix(&self, str: &str, str_pad: Option<u32>, pat: &str, pat_pad: Option<u32>) {
        let expected = str.strip_suffix(pat);

        let enc_str = FheString::new(&self.ck, str, str_pad);
        let enc_pat = FheString::new(&self.ck, pat, pat_pad);

        let start = Instant::now();
        let (result, is_some) = self.sk.strip_suffix(&enc_str, &enc_pat);
        let end = Instant::now();

        let dec_result = self.ck.decrypt_ascii(&result);
        let dec_is_some = self.ck.key().decrypt_bool(&is_some);

        let dec = if dec_is_some { Some(dec_result.as_str()) } else { None };

        println!(
            "\n\x1b[1;37;1mStrip_suffix:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mPattern: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, pat, expected, dec, end.duration_since(start)
        );

        assert_eq!(dec, expected);
    }

    pub fn assert_eq_ignore_case(&self, str: &str, str_pad: Option<u32>, rhs: &str, rhs_pad: Option<u32>) {
        let expected = str.eq_ignore_ascii_case(rhs);

        let enc_lhs = FheString::new(&self.ck, str, str_pad);
        let enc_rhs = FheString::new(&self.ck, rhs, rhs_pad);

        let start = Instant::now();
        let result = self.sk.eq_ignore_case(&enc_lhs, &enc_rhs);
        let end = Instant::now();

        let dec = self.ck.key().decrypt_bool(&result);

        println!(
            "\n\x1b[1;37;1mEq_ignore_case:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mLhs: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mRhs: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, rhs, expected, dec, end.duration_since(start)
        );

        assert_eq!(dec, expected);
    }

    pub fn assert_comp(&self, str: &str, str_pad: Option<u32>, rhs: &str, rhs_pad: Option<u32>) {
        let enc_lhs = FheString::new(&self.ck, str, str_pad);
        let enc_rhs = FheString::new(&self.ck, rhs, rhs_pad);

        // Equal
        let expected_eq = str == rhs;

        let start = Instant::now();
        let result_eq = self.sk.eq(&enc_lhs, &enc_rhs);
        let end = Instant::now();

        let dec_eq = self.ck.key().decrypt_bool(&result_eq);

        println!(
            "\n\x1b[1;37;1mEq:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mLhs: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mRhs: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, rhs, expected_eq, dec_eq, end.duration_since(start)
        );
        assert_eq!(dec_eq, expected_eq);

        // Not equal
        let expected_ne = str != rhs;

        let start = Instant::now();
        let result_ne = self.sk.ne(&enc_lhs, &enc_rhs);
        let end = Instant::now();

        let dec_ne = self.ck.key().decrypt_bool(&result_ne);

        println!(
            "\n\x1b[1;37;1mNe:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mLhs: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mRhs: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, rhs, expected_ne, dec_ne, end.duration_since(start)
        );
        assert_eq!(dec_ne, expected_ne);

        // Greater or equal
        let expected_ge = str >= rhs;

        let start = Instant::now();
        let result_ge = self.sk.ge(&enc_lhs, &enc_rhs);
        let end = Instant::now();

        let dec_ge = self.ck.key().decrypt_bool(&result_ge);

        println!(
            "\n\x1b[1;37;1mGe:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mLhs: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mRhs: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, rhs, expected_ge, dec_ge, end.duration_since(start)
        );
        assert_eq!(dec_ge, expected_ge);

        // Less or equal
        let expected_le = str <= rhs;

        let start = Instant::now();
        let result_le = self.sk.le(&enc_lhs, &enc_rhs);
        let end = Instant::now();

        let dec_le = self.ck.key().decrypt_bool(&result_le);

        println!(
            "\n\x1b[1;37;1mLe:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mLhs: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mRhs: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, rhs, expected_le, dec_le, end.duration_since(start)
        );
        assert_eq!(dec_le, expected_le);

        // Greater than
        let expected_gt = str > rhs;

        let start = Instant::now();
        let result_gt = self.sk.gt(&enc_lhs, &enc_rhs);
        let end = Instant::now();

        let dec_gt = self.ck.key().decrypt_bool(&result_gt);

        println!(
            "\n\x1b[1;37;1mGt:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mLhs: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mRhs: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, rhs, expected_gt, dec_gt, end.duration_since(start)
        );
        assert_eq!(dec_gt, expected_gt);

        // Less than
        let expected_lt = str < rhs;

        let start = Instant::now();
        let result_lt = self.sk.lt(&enc_lhs, &enc_rhs);
        let end = Instant::now();

        let dec_lt = self.ck.key().decrypt_bool(&result_lt);

        println!(
            "\n\x1b[1;37;1mLt:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mLhs: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mRhs: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, rhs, expected_lt, dec_lt, end.duration_since(start)
        );
        assert_eq!(dec_lt, expected_lt);
    }

    pub fn assert_to_lowercase(&self, str: &str, str_pad: Option<u32>) {
        let expected = str.to_lowercase();

        let enc_str = FheString::new(&self.ck, str, str_pad);

        let start = Instant::now();
        let result = self.sk.to_lowercase(&enc_str);
        let end = Instant::now();

        let dec = self.ck.decrypt_ascii(&result);

        println!(
            "\n\x1b[1;37;1mTo_lowercase:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, expected, dec, end.duration_since(start)
        );

        assert_eq!(dec, expected);
    }

    pub fn assert_to_uppercase(&self, str: &str, str_pad: Option<u32>) {
        let expected = str.to_uppercase();

        let enc_str = FheString::new(&self.ck, str, str_pad);

        let start = Instant::now();
        let result = self.sk.to_uppercase(&enc_str);
        let end = Instant::now();

        let dec = self.ck.decrypt_ascii(&result);

        println!(
            "\n\x1b[1;37;1mTo_uppercase:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, expected, dec, end.duration_since(start)
        );

        assert_eq!(dec, expected);
    }

    pub fn assert_concat(&self, str: &str, str_pad: Option<u32>, rhs: &str, rhs_pad: Option<u32>) {
        let expected = str.to_owned() + rhs;

        let enc_lhs = FheString::new(&self.ck, str, str_pad);
        let enc_rhs = FheString::new(&self.ck, rhs, rhs_pad);

        let start = Instant::now();
        let result = self.sk.concat(&enc_lhs, &enc_rhs);
        let end = Instant::now();

        let dec = self.ck.decrypt_ascii(&result);

        println!(
            "\n\x1b[1;37;1mConcat (+):\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mLhs: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mRhs: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, rhs, expected, dec, end.duration_since(start)
        );

        assert_eq!(dec, expected);
    }

    pub fn assert_repeat(&self, str: &str, str_pad: Option<u32>, n: u16, max: u16) {
        let expected = str.repeat(n as usize);

        let enc_str = FheString::new(&self.ck, str, str_pad);

        // Clear n
        let start = Instant::now();
        let result = self.sk.repeat(&enc_str, &UIntArg::Clear(n));
        let end = Instant::now();

        let dec = self.ck.decrypt_ascii(&result);

        println!(
            "\n\x1b[1;37;1mRepeat:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mTimes (clear): \x1b[0m{}\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}",
            str, n, expected, dec, end.duration_since(start)
        );
        assert_eq!(dec, expected);

        // Encrypted n
        let enc_n = self.ck.encrypt_u16(n, Some(max));

        let start = Instant::now();
        let result = self.sk.repeat(&enc_str, &UIntArg::Enc(enc_n));
        let end = Instant::now();

        let dec = self.ck.decrypt_ascii(&result);

        println!(
            "\n\x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mTimes (encrypted): \x1b[0m{}\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, n, expected, dec, end.duration_since(start)
        );
        assert_eq!(dec, expected);
    }

    pub fn assert_trim_end(&self, str: &str, str_pad: Option<u32>) {
        let expected = str.trim_end();

        let enc_str = FheString::new(&self.ck, str, str_pad);

        let start = Instant::now();
        let result = self.sk.trim_end(&enc_str);
        let end = Instant::now();

        let dec = self.ck.decrypt_ascii(&result);

        println!(
            "\n\x1b[1;37;1mTrim_end:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, expected, dec, end.duration_since(start)
        );

        assert_eq!(dec, expected);
    }

    pub fn assert_trim_start(&self, str: &str, str_pad: Option<u32>) {
        let expected = str.trim_start();

        let enc_str = FheString::new(&self.ck, str, str_pad);

        let start = Instant::now();
        let result = self.sk.trim_start(&enc_str);
        let end = Instant::now();

        let dec = self.ck.decrypt_ascii(&result);

        println!(
            "\n\x1b[1;37;1mTrim_start:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, expected, dec, end.duration_since(start)
        );

        assert_eq!(dec, expected);
    }

    pub fn assert_trim(&self, str: &str, str_pad: Option<u32>) {
        let expected = str.trim();

        let enc_str = FheString::new(&self.ck, str, str_pad);

        let start = Instant::now();
        let result = self.sk.trim(&enc_str);
        let end = Instant::now();

        let dec = self.ck.decrypt_ascii(&result);

        println!(
            "\n\x1b[1;37;1mTrim:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, expected, dec, end.duration_since(start)
        );

        assert_eq!(dec, expected);
    }

    pub fn assert_split_ascii_whitespace(&self, str: &str, str_pad: Option<u32>) {
        let mut expected: Vec<_> = str.split_ascii_whitespace().map(Some).collect();
        expected.push(None);

        let enc_str = FheString::new(&self.ck, str, str_pad);

        let mut results = Vec::with_capacity(expected.len());

        // Call next enough times
        let start = Instant::now();
        let mut split_iter = self.sk.split_ascii_whitespace(&enc_str);
        for _ in 0..expected.len() {

            results.push(split_iter.next(&self.sk))
        }
        let end = Instant::now();

        // Collect the decrypted results
        let dec: Vec<_> = results.iter().map(|result| {
            self.ck.decrypt_ascii(result)
        }).collect();

        // Split_ascii_whitespace returns "" in the None case (temporarily)
        assert_eq!(dec.last().unwrap(), "");

        let mut dec_option: Vec<Option<&str>> = Vec::with_capacity(dec.len());
        for (i, string) in dec.iter().enumerate() {
            if i < dec.len() - 1 {
                dec_option.push(Some(string));
            } else {
                dec_option.push(None);
            }
        }

        println!(
            "\n\x1b[1;37;1mSplit_ascii_whitespace:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, expected, dec_option, end.duration_since(start)
        );

        assert_eq!(dec_option, expected);
    }

    pub fn assert_split_once(&self, str: &str, str_pad: Option<u32>, pat: &str, pat_pad: Option<u32>) {
        let expected = str.split_once(pat);

        let enc_str = FheString::new(&self.ck, str, str_pad);
        let enc_pat = FheString::new(&self.ck, pat, pat_pad);

        let start = Instant::now();
        let (lhs, rhs, is_some) = self.sk.split_once(&enc_str, &enc_pat);
        let end = Instant::now();

        let dec_lhs = self.ck.decrypt_ascii(&lhs);
        let dec_rhs = self.ck.decrypt_ascii(&rhs);
        let dec_is_some = self.ck.key().decrypt_bool(&is_some);

        let dec = if dec_is_some { Some((dec_lhs.as_str(), dec_rhs.as_str())) } else { None };

        println!(
            "\n\x1b[1;37;1mSplit_once:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mPattern: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, pat, expected, dec, end.duration_since(start)
        );

        assert_eq!(dec, expected);
    }

    pub fn assert_rsplit_once(&self, str: &str, str_pad: Option<u32>, pat: &str, pat_pad: Option<u32>) {
        let expected = str.rsplit_once(pat);

        let enc_str = FheString::new(&self.ck, str, str_pad);
        let enc_pat = FheString::new(&self.ck, pat, pat_pad);

        let start = Instant::now();
        let (lhs, rhs, is_some) = self.sk.rsplit_once(&enc_str, &enc_pat);
        let end = Instant::now();

        let dec_lhs = self.ck.decrypt_ascii(&lhs);
        let dec_rhs = self.ck.decrypt_ascii(&rhs);
        let dec_is_some = self.ck.key().decrypt_bool(&is_some);

        let dec = if dec_is_some { Some((dec_lhs.as_str(), dec_rhs.as_str())) } else { None };

        println!(
            "\n\x1b[1;37;1mRsplit_once:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mPattern: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, pat, expected, dec, end.duration_since(start)
        );

        assert_eq!(dec, expected);
    }

    pub fn assert_split(&self, str: &str, str_pad: Option<u32>, pat: &str, pat_pad: Option<u32>) {
        let mut expected: Vec<_> = str.split(pat).map(Some).collect();
        expected.push(None);

        let enc_str = FheString::new(&self.ck, str, str_pad);
        let enc_pat = FheString::new(&self.ck, pat, pat_pad);

        let mut results = Vec::with_capacity(expected.len());

        // Call next enough times
        let start = Instant::now();
        let mut split_iter = self.sk.split(&enc_str, &enc_pat);
        for _ in 0..expected.len() {

            results.push(split_iter.next(&self.sk))
        }
        let end = Instant::now();

        // Collect the decrypted results properly
        let dec: Vec<_> = results.iter().map(|(result, is_some)| {
            let dec_is_some = self.ck.key().decrypt_bool(is_some);

            if dec_is_some {
                Some(self.ck.decrypt_ascii(result))
            } else {
                None
            }
        }).collect();

        println!(
            "\n\x1b[1;37;1mSplit:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mPattern: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, pat, expected, dec, end.duration_since(start)
        );

        let dec_as_str: Vec<_> = dec.iter()
            .map(|option| option.as_ref().map(|s| s.as_str()))
            .collect();

        assert_eq!(dec_as_str, expected);
    }

    pub fn assert_rsplit(&self, str: &str, str_pad: Option<u32>, pat: &str, pat_pad: Option<u32>) {
        let mut expected: Vec<_> = str.rsplit(pat).map(Some).collect();
        expected.push(None);

        let enc_str = FheString::new(&self.ck, str, str_pad);
        let enc_pat = FheString::new(&self.ck, pat, pat_pad);

        let mut results = Vec::with_capacity(expected.len());

        // Call next enough times
        let start = Instant::now();
        let mut split_iter = self.sk.rsplit(&enc_str, &enc_pat);
        for _ in 0..expected.len() {

            results.push(split_iter.next(&self.sk))
        }
        let end = Instant::now();

        // Collect the decrypted results properly
        let dec: Vec<_> = results.iter().map(|(result, is_some)| {
            let dec_is_some = self.ck.key().decrypt_bool(is_some);

            if dec_is_some {
                Some(self.ck.decrypt_ascii(result))
            } else {
                None
            }
        }).collect();

        println!(
            "\n\x1b[1;37;1mRsplit:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mPattern: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, pat, expected, dec, end.duration_since(start)
        );

        let dec_as_str: Vec<_> = dec.iter()
            .map(|option| option.as_ref().map(|s| s.as_str()))
            .collect();

        assert_eq!(dec_as_str, expected);
    }

    pub fn assert_split_terminator(&self, str: &str, str_pad: Option<u32>, pat: &str, pat_pad: Option<u32>) {
        let mut expected: Vec<_> = str.split_terminator(pat).map(Some).collect();
        expected.push(None);

        let enc_str = FheString::new(&self.ck, str, str_pad);
        let enc_pat = FheString::new(&self.ck, pat, pat_pad);

        let mut results = Vec::with_capacity(expected.len());

        // Call next enough times
        let start = Instant::now();
        let mut split_iter = self.sk.split_terminator(&enc_str, &enc_pat);
        for _ in 0..expected.len() {

            results.push(split_iter.next(&self.sk))
        }
        let end = Instant::now();

        // Collect the decrypted results properly
        let dec: Vec<_> = results.iter().map(|(result, is_some)| {
            let dec_is_some = self.ck.key().decrypt_bool(is_some);

            if dec_is_some {
                Some(self.ck.decrypt_ascii(result))
            } else {
                None
            }
        }).collect();

        println!(
            "\n\x1b[1;37;1mSplit_terminator:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mPattern: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, pat, expected, dec, end.duration_since(start)
        );

        let dec_as_str: Vec<_> = dec.iter()
            .map(|option| option.as_ref().map(|s| s.as_str()))
            .collect();

        assert_eq!(dec_as_str, expected);
    }

    pub fn assert_rsplit_terminator(&self, str: &str, str_pad: Option<u32>, pat: &str, pat_pad: Option<u32>) {
        let mut expected: Vec<_> = str.rsplit_terminator(pat).map(Some).collect();
        expected.push(None);

        let enc_str = FheString::new(&self.ck, str, str_pad);
        let enc_pat = FheString::new(&self.ck, pat, pat_pad);

        let mut results = Vec::with_capacity(expected.len());

        // Call next enough times
        let start = Instant::now();
        let mut split_iter = self.sk.rsplit_terminator(&enc_str, &enc_pat);
        for _ in 0..expected.len() {

            results.push(split_iter.next(&self.sk))
        }
        let end = Instant::now();

        // Collect the decrypted results properly
        let dec: Vec<_> = results.iter().map(|(result, is_some)| {
            let dec_is_some = self.ck.key().decrypt_bool(is_some);

            if dec_is_some {
                Some(self.ck.decrypt_ascii(result))
            } else {
                None
            }
        }).collect();

        println!(
            "\n\x1b[1;37;1mRsplit_terminator:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mPattern: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, pat, expected, dec, end.duration_since(start)
        );

        let dec_as_str: Vec<_> = dec.iter()
            .map(|option| option.as_ref().map(|s| s.as_str()))
            .collect();

        assert_eq!(dec_as_str, expected);
    }

    pub fn assert_split_inclusive(&self, str: &str, str_pad: Option<u32>, pat: &str, pat_pad: Option<u32>) {
        let mut expected: Vec<_> = str.split_inclusive(pat).map(Some).collect();
        expected.push(None);

        let enc_str = FheString::new(&self.ck, str, str_pad);
        let enc_pat = FheString::new(&self.ck, pat, pat_pad);

        let mut results = Vec::with_capacity(expected.len());

        // Call next enough times
        let start = Instant::now();
        let mut split_iter = self.sk.split_inclusive(&enc_str, &enc_pat);
        for _ in 0..expected.len() {

            results.push(split_iter.next(&self.sk))
        }
        let end = Instant::now();

        // Collect the decrypted results properly
        let dec: Vec<_> = results.iter().map(|(result, is_some)| {
            let dec_is_some = self.ck.key().decrypt_bool(is_some);

            if dec_is_some {
                Some(self.ck.decrypt_ascii(result))
            } else {
                None
            }
        }).collect();

        println!(
            "\n\x1b[1;37;1mSplit_inclusive:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mPattern: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, pat, expected, dec, end.duration_since(start)
        );

        let dec_as_str: Vec<_> = dec.iter()
            .map(|option| option.as_ref().map(|s| s.as_str()))
            .collect();

        assert_eq!(dec_as_str, expected);
    }

    pub fn assert_splitn(&self, str: &str, str_pad: Option<u32>, pat: &str, pat_pad: Option<u32>, n: u16, max: u16) {
        let mut expected: Vec<_> = str.splitn(n as usize, pat).map(Some).collect();
        expected.push(None);

        let enc_str = FheString::new(&self.ck, str, str_pad);
        let enc_pat = FheString::new(&self.ck, pat, pat_pad);

        let mut results = Vec::with_capacity(expected.len());

        // Call next enough times
        let start = Instant::now();
        let mut split_iter = self.sk.splitn(&enc_str, &enc_pat, UIntArg::Clear(n));
        for _ in 0..expected.len() {

            results.push(split_iter.next(&self.sk))
        }
        let end = Instant::now();

        // Collect the decrypted results properly
        let dec: Vec<_> = results.iter().map(|(result, is_some)| {
            let dec_is_some = self.ck.key().decrypt_bool(is_some);

            if dec_is_some { Some(self.ck.decrypt_ascii(result))
            } else {
                None
            }
        }).collect();

        println!(
            "\n\x1b[1;37;1mSplitn:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mPattern: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mTimes (clear): \x1b[0m{}\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}",
            str, pat, n, expected, dec, end.duration_since(start)
        );

        let dec_as_str: Vec<_> = dec.iter()
            .map(|option| option.as_ref().map(|s| s.as_str()))
            .collect();

        assert_eq!(dec_as_str, expected);

        let enc_n = self.ck.encrypt_u16(n, Some(max));
        results.clear();

        // Call next enough times
        let start = Instant::now();
        let mut split_iter = self.sk.splitn(&enc_str, &enc_pat, UIntArg::Enc(enc_n));
        for _ in 0..expected.len() {

            results.push(split_iter.next(&self.sk))
        }
        let end = Instant::now();

        // Collect the decrypted results properly
        let dec: Vec<_> = results.iter().map(|(result, is_some)| {
            let dec_is_some = self.ck.key().decrypt_bool(is_some);

            if dec_is_some {
                Some(self.ck.decrypt_ascii(result))
            } else {
                None
            }
        }).collect();

        println!(
            "\n\x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mPattern: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mTimes (encrypted): \x1b[0m{}\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, pat, n, expected, dec, end.duration_since(start)
        );

        let dec_as_str: Vec<_> = dec.iter()
            .map(|option| option.as_ref().map(|s| s.as_str()))
            .collect();

        assert_eq!(dec_as_str, expected);
    }

    pub fn assert_rsplitn(&self, str: &str, str_pad: Option<u32>, pat: &str, pat_pad: Option<u32>, n: u16, max: u16) {
        let mut expected: Vec<_> = str.rsplitn(n as usize, pat).map(Some).collect();
        expected.push(None);

        let enc_str = FheString::new(&self.ck, str, str_pad);
        let enc_pat = FheString::new(&self.ck, pat, pat_pad);

        let mut results = Vec::with_capacity(expected.len());

        // Call next enough times
        let start = Instant::now();
        let mut split_iter = self.sk.rsplitn(&enc_str, &enc_pat, UIntArg::Clear(n));
        for _ in 0..expected.len() {

            results.push(split_iter.next(&self.sk))
        }
        let end = Instant::now();

        // Collect the decrypted results properly
        let dec: Vec<_> = results.iter().map(|(result, is_some)| {
            let dec_is_some = self.ck.key().decrypt_bool(is_some);

            if dec_is_some { Some(self.ck.decrypt_ascii(result))
            } else {
                None
            }
        }).collect();

        println!(
            "\n\x1b[1;37;1mRsplitn:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mPattern: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mTimes (clear): \x1b[0m{}\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}",
            str, pat, n, expected, dec, end.duration_since(start)
        );

        let dec_as_str: Vec<_> = dec.iter()
            .map(|option| option.as_ref().map(|s| s.as_str()))
            .collect();

        assert_eq!(dec_as_str, expected);

        let enc_n = self.ck.encrypt_u16(n, Some(max));
        results.clear();

        // Call next enough times
        let start = Instant::now();
        let mut split_iter = self.sk.rsplitn(&enc_str, &enc_pat, UIntArg::Enc(enc_n));
        for _ in 0..expected.len() {

            results.push(split_iter.next(&self.sk))
        }
        let end = Instant::now();

        // Collect the decrypted results properly
        let dec: Vec<_> = results.iter().map(|(result, is_some)| {
            let dec_is_some = self.ck.key().decrypt_bool(is_some);

            if dec_is_some {
                Some(self.ck.decrypt_ascii(result))
            } else {
                None
            }
        }).collect();

        println!(
            "\n\x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mPattern: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mTimes (encrypted): \x1b[0m{}\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, pat, n, expected, dec, end.duration_since(start)
        );

        let dec_as_str: Vec<_> = dec.iter()
            .map(|option| option.as_ref().map(|s| s.as_str()))
            .collect();

        assert_eq!(dec_as_str, expected);
    }

    pub fn assert_replace(&self, str: &str, str_pad: Option<u32>, pat: &str, pat_pad: Option<u32>, to: &str, to_pad: Option<u32>) {
        let expected = str.replace(pat, to);

        let enc_str = FheString::new(&self.ck, str, str_pad);
        let enc_pat = FheString::new(&self.ck, pat, pat_pad);
        let enc_to = FheString::new(&self.ck, to, to_pad);

        let start = Instant::now();
        let result = self.sk.replace(&enc_str, &enc_pat, &enc_to);
        let end = Instant::now();

        let dec = self.ck.decrypt_ascii(&result);

        println!(
            "\n\x1b[1;37;1mReplace:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mFrom: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mTo: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, pat, to, expected, dec, end.duration_since(start)
        );

        assert_eq!(dec, expected);
    }

    pub fn assert_replacen(&self, str: (&str, Option<u32>), pat: (&str, Option<u32>), to: (&str, Option<u32>), n: u16, max: u16) {
        let (str, str_pad) = (str.0, str.1);
        let (pat, pat_pad) = (pat.0, pat.1);
        let (to, to_pad) = (to.0, to.1);

        let expected = str.replacen(pat, to, n as usize);

        let enc_str = FheString::new(&self.ck, str, str_pad);
        let enc_pat = FheString::new(&self.ck, pat, pat_pad);
        let enc_to = FheString::new(&self.ck, to, to_pad);

        let start = Instant::now();
        let result = self.sk.replacen(&enc_str, &enc_pat, &enc_to, &UIntArg::Clear(n));
        let end = Instant::now();

        let dec = self.ck.decrypt_ascii(&result);

        println!(
            "\n\x1b[1;37;1mReplacen:\x1b[0m\n\
    \x1b[1;32m--------------------------------\x1b[0m\n\
    \x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mFrom: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mTo: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mTimes (clear): \x1b[0m{}\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}",
            str, pat, to, n, expected, dec, end.duration_since(start)
        );
        assert_eq!(dec, expected);

        let enc_n = self.ck.encrypt_u16(n, Some(max));

        let start = Instant::now();
        let result = self.sk.replacen(&enc_str, &enc_pat, &enc_to, &UIntArg::Enc(enc_n));
        let end = Instant::now();

        let dec = self.ck.decrypt_ascii(&result);

        println!(
            "\n\x1b[1;32;1mString: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mFrom: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mTo: \x1b[0m\x1b[0;33m\"{}\"\x1b[0m\n\
    \x1b[1;32;1mTimes (encrypted): \x1b[0m{}\n\
    \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
    \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
    \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
    \x1b[1;32m--------------------------------\x1b[0m",
            str, pat, to, n, expected, dec, end.duration_since(start)
        );
        assert_eq!(dec, expected);
    }
}