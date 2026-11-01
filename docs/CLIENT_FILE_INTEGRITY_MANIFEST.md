# Client file-integrity manifest

The checked-in header at `client/include/file_integrity_manifest.generated.h` is deliberately a placeholder template. The existing `RRO.exe` digest should not be assumed to match your actual production package. File-integrity enforcement remains disabled by default; when enabled, the client rejects an incomplete or invalid manifest at startup.

## Generate hashes from the exact production package

Use the same unmodified game directory that will be packaged and distributed to players. From the repository root, run:

```powershell
python tools/generate_integrity_manifest.py "D:\path\to\your\Ragnarok-client"
```

The tool hashes exactly these files with streaming SHA-256: `RRO.exe`, `en.grf`, and `DATA.ini`. It writes the computed values to `client/include/file_integrity_manifest.generated.h`. It refuses to write a partial header if any required file is missing, unreadable, or a symbolic link. The current header remains unchanged on validation failure.

Review the printed hashes, confirm that the directory is the actual release package (not a developer or patched copy), and rebuild the client after generating the header. Repeat this process for each distinct package/version; changing any monitored file requires regenerating the manifest and rebuilding the client.

## Before enabling enforcement

1. Verify that all three header values are 64 hexadecimal SHA-256 characters and none is `PLACEHOLDER`.
2. Check the generator's size warning. The runtime currently refuses to enforce hashing a monitored file larger than 512 MiB. If a production file exceeds that limit, review and update `kMaxHashFileSizeBytes` in `client/src/file_integrity_check.cpp`, then rebuild and retest; do not ignore the warning.
3. Build the production Release client with `OBLIVION_ENFORCE_FILE_INTEGRITY=1` defined for that configuration.
4. Test startup and file mismatch behavior against the exact packaged game, including patcher/antivirus file locks, before distributing.

The generator does not invent hashes and does not enable enforcement itself. The production package is required to produce the final values. If the manifest is incomplete and enforcement is enabled, startup is intentionally refused rather than silently skipping a file.
