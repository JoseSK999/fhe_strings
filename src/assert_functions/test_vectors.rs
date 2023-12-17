use crate::Keys;

const TEST_CASES_MATCH: [(&str, u32); 15] = [
    ("", 0), ("", 1), ("", 2), ("", 3), ("a", 0), ("a", 1),
    ("o", 2), (" ", 2), ("I F*", 3), ("<3", 3), ("foo", 0), ("foofoo", 0), ("foofoo", 1),
    (" zelda", 12), ("I F*** <3 zelda", 0),
];

const TEST_WHITESPACE: [(&str, u32); 17] = [
    ("", 0), ("", 1), ("", 2), ("", 3),
    (" ", 0), (" ", 1),
    ("\n", 0), ("\n", 1),
    ("\t", 0), ("\t", 1),
    ("\r", 0), ("\r", 1),
    ("\u{000C}", 0), ("\u{000C}", 1),
    ("viv4_crist0_rey!", 1),
    (" \t\u{000C}\r\n viv4 crist0\t\r\u{000C}\n rey! \t\u{000C}\n \r", 0),
    (" \t\u{000C}\r\n viv4 crist0\t\r\u{000C}\n rey! \t\u{000C}\n \r", 1),
];

const TEST_CASES_COMP: [(&str, u32); 15] = [
    ("", 0), ("", 1), ("", 2), ("", 3), ("a", 0), ("a", 1), ("a", 10),
    ("foo", 0), ("foofoo4", 0), ("foofoo4", 1), ("foofoo4", 2),
    ("FooFoo4", 0), ("FooFoo4", 1), ("foofoo44", 0), ("foofoo44", 1),
];

const TEST_CASES_SPLIT: [((&str, u32), (&str, u32), u32); 21] = [
    // Empty strings and patterns with different paddings to test edge cases
    (("", 0), ("", 0), 3), (("", 0), ("", 1), 3), (("", 0), ("", 2), 3),
    (("", 1), ("", 0), 3), (("", 1), ("", 1), 3), (("", 1), ("", 2), 3),
    (("", 2), ("", 0), 3), (("", 2), ("", 1), 3), (("", 2), ("", 2), 3),

    // More edge cases involving the empty string and pattern
    (("", 0), ("a", 0), 2), (("", 1), ("a", 0), 2), (("", 2), ("a", 0), 2),
    (("Kikwi", 0), ("", 0), 8), (("Bucha", 0), ("", 1), 8), (("Yerbal", 0), ("", 2), 9),

    (("aaa", 0), ("a", 0), 5),
    (("aaa", 0), ("aa", 0), 3),
    (("Deep Woods", 0), ("woods", 0), 2),
    (("Skyview Temple", 0), ("e", 2), 5),
    (("Lake.Floria.", 2), (".", 1), 4),
    (("Ghirahim", 2), ("hi", 0), 4),
];

const TEST_CASES_REPLACE: [((&str, u32), (&str, u32), (&str, u32)); 28] = [
    // Empty string matches with different padding combinations
    (("", 0), ("", 0), ("", 0)),
    (("", 1), ("", 0), ("", 0)),
    (("", 2), ("", 0), ("", 0)),

    (("", 0), ("", 1), ("{}", 0)),
    (("", 1), ("", 1), ("{}", 0)),
    (("", 2), ("", 1), ("{}", 0)),

    (("", 0), ("", 2), ("<3", 0)),
    (("", 1), ("", 2), ("<3", 0)),
    (("", 2), ("", 2), ("<3", 0)),

    (("aa", 0), ("", 0), ("|", 0)),
    (("aa", 0), ("", 1), ("|", 0)),
    (("aa", 0), ("", 2), ("|", 0)),
    (("aa", 0), ("", 2), ("|", 1)),

    // Non empty string matches
    (("a", 0), ("a", 0), ("A", 0)),
    (("a", 2), ("a", 2), ("A", 1)),

    (("@1@2", 0), ("@", 2), ("", 0)),
    (("@1@2", 0), ("@", 2), ("", 1)),
    (("@1@2", 0), ("@", 2), ("", 2)),

    (("Bokoblin", 0), ("Boko", 0), ("Bul", 0)),
    (("Bokoblin", 0), ("Boko", 0), ("Bul", 1)),

    // Cases where `from` is contained in `to`
    (("abab", 1), ("b", 0), ("ab", 0)),
    (("Keese", 1), ("e", 1), ("ee", 0)),
    (("Keese", 1), ("ee", 0), ("Keese", 1)),

    // Cases with no match
    (("Keese", 1), ("Keesee", 0), ("Keese", 0)),
    (("Keese", 1), ("k", 0), ("K", 0)),
    (("", 0), ("k", 0), ("K", 0)),
    (("", 1), ("k", 0), ("K", 0)),
    (("", 2), ("k", 0), ("K", 0)),
];

#[test]
fn test_len() {
    let keys = Keys::new();

    for (str, str_pad) in TEST_CASES_MATCH {
        keys.assert_len(str, Some(str_pad));
    }
}

#[test]
fn test_is_empty() {
    let keys = Keys::new();

    for (str, str_pad) in TEST_CASES_MATCH {
        keys.assert_is_empty(str, Some(str_pad));
    }
}

#[test]
fn test_contains() {
    let keys = Keys::new();

    // 225 different cases
    for (str, str_pad) in TEST_CASES_MATCH {
        for (pat, pat_pad) in TEST_CASES_MATCH {

            keys.assert_contains(str, Some(str_pad), pat, Some(pat_pad));
        }
    }
}

#[test]
fn test_ends_with() {
    let keys = Keys::new();

    // 225 different cases
    for (str, str_pad) in TEST_CASES_MATCH {
        for (pat, pat_pad) in TEST_CASES_MATCH {

            keys.assert_ends_with(str, Some(str_pad), pat, Some(pat_pad));
        }
    }
}

#[test]
fn test_starts_with() {
    let keys = Keys::new();

    // 225 different cases
    for (str, str_pad) in TEST_CASES_MATCH {
        for (pat, pat_pad) in TEST_CASES_MATCH {

            keys.assert_starts_with(str, Some(str_pad), pat, Some(pat_pad));
        }
    }
}

#[test]
fn test_strip_prefix() {
    let keys = Keys::new();

    // 225 different cases
    for (str, str_pad) in TEST_CASES_MATCH {
        for (pat, pat_pad) in TEST_CASES_MATCH {

            keys.assert_strip_prefix(str, Some(str_pad), pat, Some(pat_pad));
        }
    }
}

#[test]
fn test_strip_suffix() {
    let keys = Keys::new();

    // 225 different cases
    for (str, str_pad) in TEST_CASES_MATCH {
        for (pat, pat_pad) in TEST_CASES_MATCH {

            keys.assert_strip_suffix(str, Some(str_pad), pat, Some(pat_pad));
        }
    }
}

#[test]
fn test_rfind() {
    let keys = Keys::new();

    // 225 different cases
    for (str, str_pad) in TEST_CASES_MATCH {
        for (pat, pat_pad) in TEST_CASES_MATCH {

            keys.assert_rfind(str, Some(str_pad), pat, Some(pat_pad));
        }
    }
}

#[test]
fn test_find() {
    let keys = Keys::new();

    // 225 different cases
    for (str, str_pad) in TEST_CASES_MATCH {
        for (pat, pat_pad) in TEST_CASES_MATCH {

            keys.assert_find(str, Some(str_pad), pat, Some(pat_pad));
        }
    }
}

#[test]
fn test_trim() {
    let keys = Keys::new();

    for (str, str_pad) in TEST_WHITESPACE {
        keys.assert_trim(str, Some(str_pad));
    }
}

#[test]
fn test_trim_start() {
    let keys = Keys::new();

    for (str, str_pad) in TEST_WHITESPACE {
        keys.assert_trim_start(str, Some(str_pad));
    }
}

#[test]
fn test_trim_end() {
    let keys = Keys::new();

    for (str, str_pad) in TEST_WHITESPACE {
        keys.assert_trim_end(str, Some(str_pad));
    }
}

#[test]
fn test_comparisons() {
    let keys = Keys::new();

    for (str, str_pad) in TEST_CASES_COMP {
        for (rhs, rhs_pad) in TEST_CASES_COMP {

            keys.assert_comp(str, Some(str_pad), rhs, Some(rhs_pad));
        }
    }
}

#[test]
fn test_to_lowercase() {
    let keys = Keys::new();

    for (str, str_pad) in TEST_CASES_COMP {
        keys.assert_to_lowercase(str, Some(str_pad));
    }
}

#[test]
fn test_to_uppercase() {
    let keys = Keys::new();

    for (str, str_pad) in TEST_CASES_COMP {
        keys.assert_to_uppercase(str, Some(str_pad));
    }
}

#[test]
fn test_eq_ignore_case() {
    let keys = Keys::new();

    for (str, str_pad) in TEST_CASES_COMP {
        for (rhs, rhs_pad) in TEST_CASES_COMP {

            keys.assert_eq_ignore_case(str, Some(str_pad), rhs, Some(rhs_pad));
        }
    }
}

#[test]
fn test_split_ascii_whitespace() {
    let keys = Keys::new();

    for (str, str_pad) in TEST_WHITESPACE {
        keys.assert_split_ascii_whitespace(str, Some(str_pad));
    }
}

#[test]
fn test_rsplit_once() {
    let keys = Keys::new();

    for (str, str_pad) in TEST_CASES_MATCH {
        for (pat, pat_pad) in TEST_CASES_MATCH {

            keys.assert_rsplit_once(str, Some(str_pad), pat, Some(pat_pad));
        }
    }
}

#[test]
fn test_split_once() {
    let keys = Keys::new();

    for (str, str_pad) in TEST_CASES_MATCH {
        for (pat, pat_pad) in TEST_CASES_MATCH {

            keys.assert_split_once(str, Some(str_pad), pat, Some(pat_pad));
        }
    }
}

#[test]
fn test_rsplit_real() {
    let keys = Keys::new();

    for ((str, str_pad), (pat, pat_pad), _) in TEST_CASES_SPLIT {
        keys.assert_rsplit(str, Some(str_pad), pat, Some(pat_pad));
    }
}

#[test]
fn test_split_real() {
    let keys = Keys::new();

    for ((str, str_pad), (pat, pat_pad), _) in TEST_CASES_SPLIT {
        keys.assert_split(str, Some(str_pad), pat, Some(pat_pad));
    }
}

#[test]
fn test_rsplitn() {
    let keys = Keys::new();

    for ((str, str_pad), (pat, pat_pad), _) in TEST_CASES_SPLIT {

        for n in 0..=3 {
            keys.assert_rsplitn(str, Some(str_pad), pat, Some(pat_pad), n, 3);
        }
    }
}

#[test]
fn test_splitn() {
    let keys = Keys::new();

    for ((str, str_pad), (pat, pat_pad), _) in TEST_CASES_SPLIT {

        for n in 0..=3 {
            keys.assert_splitn(str, Some(str_pad), pat, Some(pat_pad), n, 3);
        }
    }
}

#[test]
fn test_split_terminator() {
    let keys = Keys::new();

    for ((str, str_pad), (pat, pat_pad), _) in TEST_CASES_SPLIT {
        keys.assert_split_terminator(str, Some(str_pad), pat, Some(pat_pad));
    }
}

#[test]
fn test_rsplit_terminator() {
    let keys = Keys::new();

    for ((str, str_pad), (pat, pat_pad), _) in TEST_CASES_SPLIT {
        keys.assert_rsplit_terminator(str, Some(str_pad), pat, Some(pat_pad));
    }
}

#[test]
fn test_split_inclusive() {
    let keys = Keys::new();

    for ((str, str_pad), (pat, pat_pad), _) in TEST_CASES_SPLIT {
        keys.assert_split_inclusive(str, Some(str_pad), pat, Some(pat_pad));
    }
}

#[test]
fn test_concat() {
    let keys = Keys::new();

    for (str, str_pad) in [("", 0), ("", 1), ("", 2), ("A", 0), ("a", 1), ("Techno", 0), ("Cursed", 2)] {
        for (rhs, rhs_pad) in [("", 0), ("", 1), ("", 2), ("W", 0), (" ", 1), (" Bokoblins", 0), ("blins", 3)] {

            keys.assert_concat(str, Some(str_pad), rhs, Some(rhs_pad));
        }
    }
}

#[test]
fn test_repeat() {
    let keys = Keys::new();

    for ((str, str_pad), n) in [(("", 0), 3), (("", 1), 3), (("", 2), 3), (("A", 0), 4), (("a", 1), 4),
        (("Yiga", 1), 0), (("Yiga", 1), 1), (("Eldin", 2), 2), (("<Gerudo Highlands>", 0), 4)] {

        keys.assert_repeat(str, Some(str_pad), n, 4);
    }
}

#[test]
fn test_replacen() {
    let keys = Keys::new();

    for ((str, str_pad), (from, from_pad), (to, to_pad)) in TEST_CASES_REPLACE {
        for n in 0..=2 {

            keys.assert_replacen(
                (str, Some(str_pad)),
                (from, Some(from_pad)),
                (to, Some(to_pad)),
                n, 2,
            );
        }
    }
}

#[test]
fn test_replace() {
    let keys = Keys::new();

    for ((str, str_pad), (from, from_pad), (to, to_pad)) in TEST_CASES_REPLACE {

        keys.assert_replace(str, Some(str_pad), from, Some(from_pad), to, Some(to_pad));
    }
}