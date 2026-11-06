# Security review and correction plan

Reviewed branch `brown1d/security` at `eb3e2866adc55a1e8876a92e5055d5fa35a013d4`. This is a focused static review of network input, allocation, and parsing, not a complete audit. Findings are reasoned from the source; they have not been reproduced with a running server or sanitizers. An authenticated peer server is a distinct trust boundary from an ordinary client.

## Findings

### High: peer-provided password records can corrupt memory

`login.c:728-807` accepts a password record from an authenticated server in `reginfo` and stores it without checking its format. A subsequent login or password check calls `check_pass` (`login.c:367`, `login.c:938`), which passes the stored string to `b64_decode` (`util.c:342-364`). The decoder ignores the supplied output capacity and writes arbitrarily many decoded bytes into the 16-byte stack array `real` (`util.c:307-329, 345`). A long encoded record can therefore cause a stack overflow when the account is checked. A short record can also cause reads past the string in `check_pass` and the decoder; high-bit input indexes outside the 128-entry lookup table. The length assertion occurs after decoding and is not a runtime validation. Corrupted local user database records create the same exposure. Impact includes process crash and potentially code execution; exploitability has not been demonstrated.

**Fix:** validate the exact stored record format and length before use and on receipt; make the decoder accept explicit input length and output capacity, reject non-ASCII and invalid encoding, and require exactly 16 decoded bytes. Reject malformed existing database records safely. Add sanitizer tests for short, long, invalid and high-bit records, including a peer update followed by login.

### High: unbounded decompression on authenticated server links

`handler.c:316-334` feeds incoming server-link bytes to `buffer_decompress` before processing frames. `buffer.c:245-271` repeatedly grows the input buffer by 2048 bytes until the compressed input stops filling it, with no decompressed-size or work limit. A malicious or compromised authenticated peer can send highly compressible data and consume substantial memory and CPU in a single read, causing denial of service. Repeated growth also uses signed `int` sizes without overflow checks. Ordinary unauthenticated client connections do not take this compressed path.

**Fix:** enforce a bounded server receive buffer and decompression budget, process complete frames incrementally, reject oversized/incomplete frames, and use checked `size_t` arithmetic. Exercise compression bombs, fragmented frames, size boundaries and allocation failures.

### Medium: server-link allocation failures leave invalid state

`server_login.c:296-302` installs the server connection and dereferences the result of `CALLOC` without checking it. `buffer.c:284-307` returns without indicating failure if stream allocation fails, frees `zin` without clearing it if `zout` allocation fails, and merely logs zlib initialization failures. The caller proceeds as though initialization succeeded. Later read, write or cleanup paths use these pointers (`handler.c:329`, `buffer.c:315-325`). Memory pressure during a peer connection can therefore cause null dereference, use-after-free or invalid zlib cleanup, taking down the process. This is an allocation-failure path, not a demonstrated reliable remote trigger.

**Fix:** construct server state before publishing it, make initialization return success/failure, track which zlib streams initialized, clear freed pointers, and unwind safely on every failure. Add fault-injection tests for each allocation and zlib initialization failure.

### Medium: shared-file quota is bypassable at its boundary

The three upload handlers compare `shared > Max_Shared` before insertion (`add_file.c:212`, `286`, `454`), so a user at the limit can add one more file. `shared` is an unsigned short (`opennap.h:147`) and increments on insertion (`add_file.c:126`). With the quota disabled or configured at/above the counter maximum, it can wrap, invalidating accounting and quota checks and enabling continued resource consumption. The default quota is 5000 (`config.c:44`), so counter wrap is not reachable through these handlers with the default limit. File add/remove messages are excluded from the normal command flood check (`handler.c:487-490`), increasing the importance of correct quotas.

**Fix:** reject insertion at `>=` the configured limit, use a sufficiently wide checked counter, and enforce an independent hard maximum even when the configurable quota is disabled. Test all three handlers at limit minus one, limit, and counter boundaries, including batch additions.

## Implementation order and verification

1. Fix password record validation and bounded decoding first; test malformed persisted and peer-supplied records under AddressSanitizer and UndefinedBehaviorSanitizer.
2. Bound compressed input and fix server-link initialization and cleanup together; add fragmented-stream, decompression-limit and fault-injection tests.
3. Fix quota enforcement and accounting; test individual and batch file operations and removal.
4. Run the full existing test suite and a sanitizer build, then fuzz framed client commands and authenticated peer messages, including allocation-failure paths. Review other unchecked allocations and numeric conversions separately; this report does not claim they are all safe.
