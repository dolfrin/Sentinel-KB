# Security Vulnerability Disclosure — Signal Android

**To:** security@signal.org
**From:** [Your Name] — QuantumWing / Sentinel-KB
**Date:** 2026-04-13
**Subject:** 11 verified security findings in Signal Android (signalapp/Signal-Android)

---

## Summary

During development of Sentinel-KB (an open-source security scanner), we performed a combined static + AI-assisted audit of the Signal Android codebase (current `main` branch as of 2026-04-13). We identified **11 verified findings** — each confirmed by reading the actual source code and tracing code paths.

We are reporting these through responsible disclosure before any public mention. We have no intention of publishing details until you have had reasonable time to assess and address them.

| Severity | Count |
|----------|-------|
| High     | 6     |
| Medium   | 5     |

All findings include exact file paths, line numbers, and code context.

---

## High Findings

### H-1. SQLCipher KDF iteration count set to 1

**File:** `app/src/main/java/org/thoughtcrime/securesms/database/SqlCipherDatabaseHook.java`
**Lines:** 13, 20

```java
// preKey:
connection.execute("PRAGMA cipher_default_kdf_iter = 1;", null, null);
// postKey:
connection.execute("PRAGMA kdf_iter = '1';", null, null);
```

**Impact:** SQLCipher default is 256,000 iterations. With 1 iteration, an attacker who obtains the encrypted database (via `allowBackup=true`, physical access, or other vulnerability) can brute-force the key derivation orders of magnitude faster.

**Note:** We acknowledge this may be an intentional performance optimization if the database key has sufficient entropy from Android Keystore. If so, we recommend adding a code comment documenting this design decision, as the current code gives no rationale.

---

### H-2. Hardcoded fallback passphrase `"unencrypted"`

**File:** `app/src/main/java/org/thoughtcrime/securesms/crypto/MasterSecretUtil.java`
**Line:** 61

```java
public static final String UNENCRYPTED_PASSPHRASE = "unencrypted";
```

**Callers:** `KeyCachingService.java:98`, `PassphraseCreateActivity.java:47`, `PassphraseChangeActivity.java:101`

**Impact:** When no user passphrase is set, the master secret is encrypted with this known constant. Combined with H-1 (KDF=1), database encryption becomes a no-op for users without a passphrase. Any actor with access to the database file (backup extraction, forensic imaging) can decrypt it immediately.

---

### H-3. Weak KDF for passphrase encryption: SHA1-PBE with 100-iteration minimum

**File:** `app/src/main/java/org/thoughtcrime/securesms/crypto/MasterSecretUtil.java`
**Lines:** 281, 286

```java
int MINIMUM_ITERATION_COUNT   = 100;   //default for low-end devices
SecretKeyFactory skf = SecretKeyFactory.getInstance("PBEWITHSHA1AND128BITAES-CBC-BC");
```

**Impact:** For users who enable the optional passphrase feature, the passphrase-to-key derivation uses at minimum 100 iterations of SHA1-based PBE. OWASP and NIST recommend 600,000+ for PBKDF2-SHA1. On modern hardware, 100 iterations provides negligible brute-force resistance.

---

### H-4. Non-atomic secret migration (TOCTOU race condition)

**File:** `app/src/main/java/org/thoughtcrime/securesms/crypto/MasterSecretUtil.java`
**Lines:** 83–87

```java
save(context, "encryption_salt", encryptionSalt);           // commit #1
save(context, "mac_salt", macSalt);                         // commit #2
save(context, "passphrase_iterations", iterations);         // commit #3
save(context, "master_secret", encryptedAndMacdMasterSecret); // commit #4
save(context, "passphrase_initialized", true);              // commit #5
```

Each `save()` calls `SharedPreferences.edit().putString().commit()` individually. If the process is killed between commits, SharedPreferences is left in an inconsistent state — e.g., new salt with old encrypted secret, which makes the master secret unrecoverable.

**Impact:** Data loss (locked out of own messages) on crash during passphrase change. Not directly exploitable for data theft, but a correctness/availability issue in a security-critical code path.

---

### H-5. Non-constant-time MAC comparison

**File:** `app/src/main/java/org/thoughtcrime/securesms/crypto/MasterCipher.java`
**Lines:** 131, 171

```java
return Arrays.equals(ourMac, theirMac);          // line 131
if (!Arrays.equals(remoteMac, localMac))          // line 171
```

**Context:** This is the legacy MasterCipher used by the passphrase encryption feature. The modern attachment crypto in `AttachmentCipherInputStream.kt:345` correctly uses `MessageDigest.isEqual()`.

**Impact:** Timing side channel for users with passphrase enabled. Practical exploitability depends on whether an attacker can submit ciphertexts and measure decryption time, which is unlikely in the local-only passphrase context. Severity is high due to the class of vulnerability, but practical risk is medium.

---

### H-6. Domain fronting includes TLS_RSA cipher suites (no forward secrecy)

**File:** `app/src/main/java/org/thoughtcrime/securesms/push/SignalServiceNetworkAccess.kt`
**Lines:** 101–104

```kotlin
CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA
```

**Impact:** The domain fronting configuration (GMAPS, GMAIL, PLAY connection specs) includes RSA key exchange cipher suites which do not provide forward secrecy. If a fronting domain's private key is compromised (by legal order, breach, or government action), all historical traffic through that front can be decrypted retroactively. This is particularly concerning because domain fronting is used in censored regions where state-level adversaries are the primary threat.

**Fix:** Remove TLS_RSA_* suites, keep only ECDHE-based suites.

---

## Medium Findings

### M-1. HMAC-SHA1 in master secret system

**File:** `app/src/main/java/org/thoughtcrime/securesms/crypto/MasterSecretUtil.java`
**Lines:** 263, 342–343

```java
KeyGenerator generator = KeyGenerator.getInstance("HmacSHA1");
Mac hmac = Mac.getInstance("HmacSHA1");
```

**Impact:** HMAC-SHA1 is not practically broken for MAC purposes, but using HMAC-SHA256 is best practice and aligns with the security level of the rest of the system.

---

### M-2. MAC values and key material logged to logcat

**File:** `app/src/main/java/org/thoughtcrime/securesms/crypto/MasterCipher.java`
**Lines:** 129–130, 135

```java
Log.i(TAG, "Our Mac: " + Hex.toString(ourMac));
Log.i(TAG, "Thr Mac: " + Hex.toString(theirMac));
Log.w(TAG, "Macing: " + content);
```

Also: `crypto/PublicKey.java:72` logs serialized public key point.

**Impact:** Cryptographic material in logcat. On Android < 4.1, logcat is world-readable. On newer versions, accessible via ADB or crash reports. Aids forensic analysis.

---

### M-3. Thread-unsafe Cipher and Mac instances

**File:** `app/src/main/java/org/thoughtcrime/securesms/crypto/MasterCipher.java`
**Lines:** 60–62, 192–197

```java
private final Cipher encryptingCipher;
private final Cipher decryptingCipher;
private final Mac hmac;

private Mac getMac(SecretKeySpec key) {
  hmac.init(key);  // no synchronization
  return hmac;
}
```

**Impact:** JCA Cipher/Mac instances are not thread-safe. If a MasterCipher instance is shared across threads, concurrent use can corrupt ciphertext or leak bytes between operations.

---

### M-4. Null return on cryptographic failure

**File:** `app/src/main/java/org/thoughtcrime/securesms/crypto/MasterSecretUtil.java`
**Lines:** 123, 126, 191, 257, 267

```java
} catch (GeneralSecurityException e) {
  Log.w(TAG, e);
  return null; //XXX
}
```

The `//XXX` comment indicates the developers are aware this is problematic. Callers that don't check for null may proceed with unencrypted data.

---

### M-5. FileProvider grants access to entire external storage

**File:** `app/src/main/res/xml/file_provider_paths.xml`
**Line:** 6

```xml
<external-path name="external_path" path="." />
```

**Impact:** `path="."` grants FileProvider access to the root of external storage. Combined with any intent-handling vulnerability, this could serve arbitrary files from shared storage via content URI.

**Fix:** Remove the broad `external-path` entry or restrict to specific subdirectories.

---

## Methodology

These findings were identified using Sentinel-KB v0.5.0, a combined static + AI security scanner:
1. **Static scan:** 287 regex-based rules with CWE mappings, calibrated against 102 open-source projects
2. **AI deep audit:** Manual code review assisted by Claude, using a knowledge base of 2,134 real vulnerability findings extracted from professional audits by 58 firms

Every finding in this disclosure was **verified by reading the actual source code** and confirming the exact file, line number, and code path. Four initial findings were identified as false positives during verification and excluded.

---

## Disclosure Timeline

- **2026-04-13:** Findings verified, disclosure sent to security@signal.org
- **2026-05-13:** 30-day window for response/fix before any public mention
- **TBD:** Public disclosure (coordinated with Signal team)

---

## Contact

[Your Name]
[Your Email]
QuantumWing — https://github.com/[your-org]/sentinel-kb

We are happy to provide additional context, answer questions, or verify fixes.
