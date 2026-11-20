# Security Notes

SinXTan encrypts a file payload before embedding the resulting container in a lossless image. These notes describe the current implementation and its limits; they are not a security audit or a guarantee of undetectability.

## Cryptographic implementation

- **Encryption:** AES-256-GCM with a random 96-bit nonce and a 128-bit authentication tag.
- **Passphrase derivation:** Argon2id with a 32-byte random salt, 64 MiB memory cost, 3 iterations, and 4 lanes.
- **Key separation:** HKDF-SHA256 derives separate encryption and embedding keys.
- **Integrity:** AES-GCM authenticates the header and serialized metadata; individual files also carry SHA-256 checksums.
- **Extraction:** AES-GCM decryption returns plaintext only after the authentication tag is verified.

The serialized metadata is authenticated as associated data, but is not encrypted by AES-GCM. Anyone who recovers the container bytes can read that metadata.

## Limitations

- LSB embedding does not provide formal plausible deniability. Statistical steganalysis may detect that a carrier image has been modified.
- Only lossless PNG, BMP, and TIFF carriers are supported. Recompression, resizing, or image editing can damage or remove embedded data.
- A weak or reused passphrase remains vulnerable to guessing. SinXTan cannot recover a forgotten passphrase.
- Passphrases and decrypted content are handled in process memory. A compromised host can expose them.
- Temporary-file overwriting is best-effort; storage hardware, journaling, backups, and copy-on-write filesystems may retain previous data.
- The application has not received an independent security audit.

Use a strong unique passphrase and keep a separate backup of important original files. Treat the executable as unsigned software from its published release and verify its SHA-256 checksum before running it.
