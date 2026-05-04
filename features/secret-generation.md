# Secret Generation

The purpose of this feature is to securely generate secrets that 
follow the provided guidance.  

It must use a secure source of entropy (OS CSPRNG via `OsRng`).

## Command

`generate` is a top-level subcommand. It prints the generated secret to stdout.
No vault is needed.

## Options

Length:
-L<N> (default: 12)

Uppercase:
-u[<min>]

Lowercase:
-l[<min>]

Digits:
-d[<min>]

Special characters:
-s[<chars><min>]

The length flag will be followed by a number.
Each character flag will be followed by an optional number specifying the minimum number of occurrences (default: 1 when the flag is present).
The -s (symbol) flag value begins with the optional allowed special characters followed by the optional minimum count.
Examples: `-s` (default charset, min 1), `-s2` (default charset, min 2), `-s"!@#"` (charset !@#, min 1), `-s"!@#"2` (charset !@#, min 2).
If a double-quote is needed in the charset, escape it: `-s"!@#\""`.

## Defaults

When no character class flags are given:
- Uppercase: included, min 1
- Lowercase: included, min 1
- Digits: included, min 1
- Special: not included
- Length: 12

Default special character set (when -s is given without an explicit charset): `!@#$%^&*()-_=+`

## Constraint resolution

If the sum of minimum counts exceeds the specified length, the length is silently increased to accommodate all minimums.
