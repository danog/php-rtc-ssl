# OpenSSL Adapter for PHP WebRTC

[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.4-blue.svg)](https://php.net/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A secure PHP FFI wrapper for OpenSSL, specifically designed for WebRTC implementations. Provides comprehensive cryptographic support including DTLS, SRTP, and certificate management.

## Features

- **DTLS Support**: Certificate generation and fingerprint extraction
- **SRTP Security**: Key derivation for secure media transport
- **Certificate Management**: X.509 support and context creation
- **Safe FFI Interface**: Type-safe cryptographic operations

## Requirements

- PHP ≥ 8.4 with FFI extension enabled
- OpenSSL development libraries
- Linux environment (Windows/macOS support planned)

## Documentation

This component is part of the PHP WebRTC ecosystem. For full documentation:

[PHP WebRTC Documentation](https://www.quasarstream.com/php-webrtc)

## Credits

### Authors

- **Amin Yazdanpanah**  
  [aminyazdanpanah.com](https://www.aminyazdanpanah.com) |  
  [github@aminyazdanpanah.com](mailto:github@aminyazdanpanah.com)

- **Sana Moniri**  
  [GitHub](https://github.com/sanamoniri)

## Reporting Issues

Found a bug? Please report it on our [GitHub repository](https://github.com/your-repo-here/issues).

## License

MIT License. See [LICENSE](LICENSE) for details.

## References

- [OpenSSL Official Documentation](https://www.openssl.org/docs/)
- [RFC 5763: DTLS-SRTP](https://datatracker.ietf.org/doc/html/rfc5763)
- [WebRTC Security Architecture](https://webrtc-security.github.io/)