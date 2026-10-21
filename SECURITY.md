# Security Policy

## Reporting

Report security issues privately through GitHub security advisories, when enabled, or contact the maintainer through the repository profile. Please allow time for investigation and remediation before public disclosure.

## Scope

Reports about incorrect cryptographic results, handling of malformed input, key exposure, denial of service, and packaging or supply-chain issues are welcome.

## Assurance

Assurance covers functional correctness: conformance to the relevant specifications and agreement with independent implementations on shared test vectors. Constant-time execution and side-channel resistance require a separate security assessment.

`neco-sha1` supports compatibility with protocols and formats that require SHA-1. `neco-sha2` and other modern hashes are appropriate for applications that need collision resistance.

Review the suitability of these crates for the deployment environment before using them with sensitive keys.

## License

[MIT](LICENSE)
