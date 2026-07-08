# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities privately. **Do not open a public issue for a security report.**

Use GitHub's private vulnerability reporting on this repository: open the **Security** tab and choose **Report a vulnerability**. This opens a private advisory visible only to the maintainers.

Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce (proof-of-concept, affected function, sample input).
- The `ntcompress` version (`python -c "import ntcompress; print(ntcompress.__version__)"`) and your environment.

You can expect an initial acknowledgement within a few days. Once the issue is confirmed and a fix is available, we will coordinate a disclosure timeline with you.

## Supported versions

Security fixes are applied to the latest released version. Please upgrade to the most recent release before reporting.

## Scope

`ntcompress` is a compression/decompression library that parses attacker-influenced input (compressed database cells, ntdll streams). Memory-safety is bounded by the Python runtime, but decompression bombs, unbounded allocations, and infinite loops triggered by crafted input are in scope, as are integrity checks that fail to detect corruption. Please report any input that causes excessive memory or CPU use, a crash, or a silently incorrect decode.
