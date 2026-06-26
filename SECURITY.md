# Security Policy

Secure is a security review tool, but it is not a guarantee that a reviewed project is safe.

## Reporting vulnerabilities

If you find a security issue in the skill, scanners, benchmark fixture, or website, open a private report if the repository supports GitHub Security Advisories. Otherwise contact the maintainer before publishing exploit details.

Please include:

- affected file and version or commit;
- reproduction steps;
- expected and actual behavior;
- impact;
- suggested fix if known.

## Scope

In scope:

- scanner crashes or unsafe file handling;
- secret leakage in examples or generated output;
- incorrect guidance that would systematically weaken production security;
- benchmark cases that create misleading pass results.

Out of scope:

- vulnerabilities intentionally present in `benchmark/`;
- missing support for a specific framework unless it causes incorrect security claims;
- reports that only say "add more security" without code evidence.
