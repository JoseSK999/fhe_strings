> :information_source: **NOTE:** The project was updated with BooleanBlocks and better style. It can now be found at https://github.com/JoseSK999/tfhe-rs

# fhe_strings

This repo contains the implementation of a str API in FHE, featuring 30 methods. This API allows the user to:
* Encrypt the `str` with or without padding nulls (i.e. encrypted `0u8`s at the end of the string), which serve to obfuscate the length but are ignored by algorithms
* Encrypt any kind of pattern (`pat`, `from`, `to`, `rhs`) with or without padding nulls
* Encrypt the number of repetitions `n`, allowing to provide a clear `max` to restrict the range of the encrypted `n`
* Provide a cleartext pattern when algorithms can run faster. Otherwise, it's possible to trivially encrypt the pattern with `FheString::trivial`

Encrypted strings contain a flag indicating whether they have padding nulls or not. Algorithms are optimized to differentiate between the two kind of strings. For instance, in some cases we can skip entirely the FHE computations if we know the true lengths of the string or pattern.

Just like the clear str API, any encrypted string returned by a function can be used as input to other functions. For instance when `trim_start` is executed, or a `Split` iterator instance is advanced with `next`, the result will only have nulls at the end. The decryption function `decrypt_ascii` will panic if it encounters with malformed encrypted strings, including padding inconsistencies.

We have handled corner cases like empty strings and empty patterns (with and without padding), the number of repetitions `n` (clear and encrypted) being zero, etc. A complete list of tests can be found at `src/assert_functions/test_vectors.rs`.

## Usage
To run all the functions and see the comparison with the clear Rust API you can specify the following arguments:

```--str <"your str"> --pat <"your pattern"> --to <"argument used in replace"> --rhs <"used in comparisons and concat"> --n <number of repetitions> --max <clear max n>```

To optionally specify a number of padding nulls for any argument you can also use: ``--str_pad``, ``--pat_pad``, ``--to_pad`` and ``--rhs_pad``.
