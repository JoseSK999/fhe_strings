# fhe_strings

This repo contains 30 standard str functions in FHE, and allows the user to:
* Encrypt the `str` with or without padding nulls (i.e. encrypted `0u8`s at the end of the string), which just serve to obfuscate the length
* Encrypt any kind of pattern (`pat`, `from`, `to`, `rhs`) with or without padding nulls
* Encrypt the number of repetitions `n`, allowing to provide a clear `max` to restrict the range of the encrypted `n`

The padding is handled such that any encrypted string returned by functions can be used as input to other functions. For instance when `trim_start` is executed, the result is shifted left such that trimmed characters (which are now nulls) go to the end. The decryption function `decrypt_ascii` will panic if it encounters with malformed encrypted strings.

Moreover we have handled corner cases like empty strings and empty patterns (with and without padding), the number of repetitions `n` (clear and encrypted) being zero, etc.
