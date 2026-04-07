// Security audit rules for messenger applications
// ─── E2E Encryption ─────────────────────────────────────────────
export const e2eRules = [
    {
        id: "E2E-001",
        name: "Plaintext logging of keys or secrets",
        description: "Logging private keys, session state, or decrypted content leaks secrets to logcat/disk",
        severity: "critical",
        category: "E2E Encryption",
        filePatterns: ["**/*.kt", "**/*.java", "**/*.rs"],
        badPatterns: [
            { pattern: /Log\.[diwev]\(.*(?:private[Kk]ey|secret[Kk]ey|sessionJson|decrypted[Mm]sg|plaintext[Mm]sg|\.password)\s*[,)$]/, message: "Logging sensitive data (key/secret/decrypted content)" },
            { pattern: /Log\.[diwev]\(.*\$\{.*(?:accessToken|refreshToken|privateKey|secretKey|password|sessionJson)\}/, message: "Logging secret value via string interpolation" },
            { pattern: /println!\(.*(?:private_key|secret_key|session_json|decrypted|plaintext|\.password)/, message: "Rust: printing sensitive data" },
            { pattern: /tracing::(?:info|debug|warn)\!.*(?:private_key|secret_key|\.password)/, message: "Rust: tracing sensitive data" },
        ],
    },
    {
        id: "E2E-002",
        name: "Hardcoded encryption key",
        description: "Encryption keys must never be hardcoded in source",
        severity: "critical",
        category: "E2E Encryption",
        filePatterns: ["**/*.kt", "**/*.java", "**/*.rs", "**/*.ts", "**/*.js"],
        badPatterns: [
            { pattern: /(?:aes|encryption|cipher|secret)_?[Kk]ey\s*=\s*"[A-Za-z0-9+/=]{16,}"/, message: "Hardcoded encryption key" },
            { pattern: /(?:val|var|let|const)\s+\w*[Ss]ecret\w*\s*=\s*"[^"]{8,}"/, message: "Hardcoded secret value" },
        ],
    },
    {
        id: "E2E-003",
        name: "Ratchet state not persisted atomically",
        description: "If ratchet state save fails after encrypt/decrypt, messages become unrecoverable",
        severity: "high",
        category: "E2E Encryption",
        filePatterns: ["**/*Repository*.kt", "**/*Manager*.kt", "**/*Service*.kt", "**/*ViewModel*.kt"],
        badPatterns: [
            { pattern: /ratchetEncrypt\([\s\S]{0,200}(?!withSessionLock|synchronized|mutex)/, message: "Encrypt without session lock — ratchet state may desync" },
            { pattern: /ratchetDecrypt\([\s\S]{0,200}(?!withSessionLock|synchronized|mutex)/, message: "Decrypt without session lock — ratchet state may desync" },
        ],
    },
    {
        id: "E2E-004",
        name: "Missing sender verification",
        description: "Incoming messages must verify sender identity to prevent impersonation",
        severity: "high",
        category: "E2E Encryption",
        filePatterns: ["**/*Repository*.kt", "**/*Manager*.kt", "**/*Service*.kt"],
        badPatterns: [
            { pattern: /ratchetDecrypt\([\s\S]{0,500}(?!verifySender|senderHint|identityKey)/, message: "Decrypt without sender verification" },
        ],
    },
    {
        id: "E2E-005",
        name: "OPK not replenished",
        description: "One-time prekeys must be replenished after use to maintain forward secrecy",
        severity: "medium",
        category: "E2E Encryption",
        filePatterns: ["**/*.kt", "**/*.java"],
        requiredPatterns: [
            { pattern: /replenish|uploadPrekeys|prekey.*upload|refill.*opk/i, message: "No OPK replenishment logic found", filePattern: "**/*Prekey*" },
        ],
    },
    {
        id: "E2E-006",
        name: "Non-constant-time comparison for crypto values",
        description: "Comparing MACs, hashes, or tokens with == allows timing attacks",
        severity: "high",
        category: "E2E Encryption",
        filePatterns: ["**/*.kt", "**/*.java"],
        badPatterns: [
            { pattern: /(?:mac|hmac|hash|digest|signature|token)\w*\s*==\s*\w*(?:mac|hmac|hash|digest|signature|token)/i, message: "Non-constant-time comparison of crypto values — use MessageDigest.isEqual()" },
        ],
    },
];
// ─── WebRTC / P2P ───────────────────────────────────────────────
export const webrtcRules = [
    {
        id: "P2P-001",
        name: "TURN credentials in source code",
        description: "TURN server credentials must not be hardcoded",
        severity: "critical",
        category: "WebRTC/P2P",
        filePatterns: ["**/*.kt", "**/*.java", "**/*.rs", "**/*.ts", "**/*.json"],
        badPatterns: [
            { pattern: /(?:turn|stun):[^\s]*@[^\s]*/, message: "TURN/STUN URI with embedded credentials" },
            { pattern: /(?:credential|password)\s*[:=]\s*"[^"]{8,}"[\s\S]{0,100}(?:turn|stun|ice)/i, message: "Hardcoded TURN credential near ICE config" },
        ],
    },
    {
        id: "P2P-002",
        name: "ICE candidate leaks local IP",
        description: "Local/mDNS ICE candidates can leak private network topology",
        severity: "medium",
        category: "WebRTC/P2P",
        filePatterns: ["**/*.kt", "**/*.java"],
        badPatterns: [
            { pattern: /onIceCandidate[\s\S]{0,300}(?!filter|mDNS|mdns|strip|sanitize).*send/, message: "ICE candidates sent without filtering — may leak local IPs" },
        ],
    },
    {
        id: "P2P-003",
        name: "DataChannel without authentication",
        description: "DataChannel messages must be authenticated to prevent injection by TURN operator",
        severity: "high",
        category: "WebRTC/P2P",
        filePatterns: ["**/*.kt", "**/*.java"],
        badPatterns: [
            { pattern: /onMessage[\s\S]{0,200}(?:getString|payload|text)[\s\S]{0,200}(?!verify|authenticate|decrypt|ratchet)/, message: "DataChannel message processed without authentication/decryption" },
        ],
    },
    {
        id: "P2P-004",
        name: "WebRTC logging exposes SDP",
        description: "Logging SDP offers/answers can expose ICE credentials and network topology",
        severity: "medium",
        category: "WebRTC/P2P",
        filePatterns: ["**/*.kt", "**/*.java"],
        badPatterns: [
            { pattern: /Log\.[diwev]\(.*(?:sdp|SDP|description|offer|answer)[\s\S]{0,50}\.description/, message: "Logging SDP content — exposes ICE credentials" },
        ],
    },
    {
        id: "P2P-005",
        name: "No SRTP for voice/video",
        description: "WebRTC media must use SRTP encryption — disabling it exposes audio/video",
        severity: "critical",
        category: "WebRTC/P2P",
        filePatterns: ["**/*.kt", "**/*.java"],
        badPatterns: [
            { pattern: /srtp.*disable|encryption.*false|RtpTransceiver.*unencrypt/i, message: "SRTP encryption disabled for media" },
        ],
    },
    {
        id: "P2P-006",
        name: "TURN static-auth-secret in code",
        description: "TURN shared secret must come from secure config, not source code",
        severity: "critical",
        category: "WebRTC/P2P",
        filePatterns: ["**/*.kt", "**/*.java", "**/*.rs", "**/*.env"],
        badPatterns: [
            { pattern: /static.auth.secret\s*[:=]\s*["\w]{16,}/, message: "TURN static-auth-secret hardcoded" },
        ],
    },
];
// ─── Messenger-Specific ─────────────────────────────────────────
export const messengerRules = [
    {
        id: "MSG-001",
        name: "Notification leaks message content",
        description: "Push notifications must not contain plaintext message content or sender name when privacy is enabled",
        severity: "high",
        category: "Messenger",
        filePatterns: ["**/*.kt", "**/*.java"],
        badPatterns: [
            { pattern: /setContentText\(.*(?:content|body|message|text)(?!.*notificationPrivacy|.*privacy)/, message: "Notification may leak message content" },
        ],
    },
    {
        id: "MSG-002",
        name: "Delivery receipt reveals sender",
        description: "Delivery/read receipts sent via server can reveal who sent messages (breaks sealed sender)",
        severity: "high",
        category: "Messenger",
        filePatterns: ["**/*.kt", "**/*.java"],
        badPatterns: [
            { pattern: /(?:delivered|read|seen|receipt)[\s\S]{0,300}sendToServer(?!.*sealedSender|.*deliveryToken)/, message: "Delivery receipt sent via server may break sealed sender" },
        ],
    },
    {
        id: "MSG-003",
        name: "Self-destruct message persisted after expiry",
        description: "Self-destructing messages must be deleted after TTL — not just hidden in UI",
        severity: "medium",
        category: "Messenger",
        filePatterns: ["**/*.kt", "**/*.java"],
        badPatterns: [
            { pattern: /self_?[Dd]estruct[\s\S]{0,500}(?:visibility|GONE|INVISIBLE)(?!.*delete|.*remove|.*dao)/, message: "Self-destruct message hidden but not deleted from DB" },
        ],
    },
    {
        id: "MSG-004",
        name: "Panic PIN does not wipe crypto keys",
        description: "Panic PIN must wipe private keys, session state, and DB — not just clear UI",
        severity: "high",
        category: "Messenger",
        filePatterns: ["**/*.kt", "**/*.java"],
        badPatterns: [
            { pattern: /panic[Pp]in[\s\S]{0,500}(?:finish|navigate|clear)(?![\s\S]{0,200}(?:wipe|delete|destroy|removeAll))/, message: "Panic PIN handler may not fully wipe crypto material" },
        ],
    },
    {
        id: "MSG-005",
        name: "Server stores sender_id for sealed messages",
        description: "Sealed sender messages must not store sender identity on server",
        severity: "critical",
        category: "Messenger",
        filePatterns: ["**/*.rs", "**/*.ts", "**/*.js"],
        badPatterns: [
            { pattern: /is_sealed.*true[\s\S]{0,200}sender_id\s*[:=]\s*(?!None|null|nil|undefined)/, message: "Sealed message stores sender_id on server" },
        ],
    },
    {
        id: "MSG-006",
        name: "Group messages not E2E encrypted per-member",
        description: "Group messages must be encrypted individually per member — shared key is weaker",
        severity: "medium",
        category: "Messenger",
        filePatterns: ["**/*.kt", "**/*.java"],
        badPatterns: [
            { pattern: /group.*encrypt[\s\S]{0,200}(?:shared[Kk]ey|group[Kk]ey)(?!.*perMember|.*individual)/, message: "Group messages using shared key instead of per-member encryption" },
        ],
    },
    {
        id: "MSG-007",
        name: "Message content in server logs",
        description: "Server must never log message content, even encrypted ciphertext (traffic analysis)",
        severity: "high",
        category: "Messenger",
        filePatterns: ["**/*.rs"],
        badPatterns: [
            { pattern: /tracing::(?:info|debug)\!.*(?:ciphertext|message_ciphertext|content|body|payload)/, message: "Server logs message content/ciphertext" },
            { pattern: /println!\(.*(?:ciphertext|message|content|body)/, message: "Server prints message content" },
        ],
    },
];
// ─── Android Security ───────────────────────────────────────────
export const androidRules = [
    {
        id: "AND-001",
        name: "Exported component without permission",
        description: "Exported activities/services/receivers must require permissions to prevent unauthorized access",
        severity: "high",
        category: "Android",
        filePatterns: ["**/AndroidManifest.xml"],
        badPatterns: [
            { pattern: /android:exported="true"(?![\s\S]{0,200}android:permission)/, message: "Exported component without permission requirement" },
        ],
    },
    {
        id: "AND-002",
        name: "Cleartext traffic allowed",
        description: "App must enforce HTTPS — cleartext HTTP allows MITM",
        severity: "high",
        category: "Android",
        filePatterns: ["**/AndroidManifest.xml", "**/network_security_config.xml"],
        badPatterns: [
            { pattern: /android:usesCleartextTraffic="true"/, message: "Cleartext HTTP traffic allowed" },
            { pattern: /cleartextTrafficPermitted="true"/, message: "Cleartext traffic permitted in network security config" },
        ],
    },
    {
        id: "AND-003",
        name: "Backup enabled (leaks encrypted DB)",
        description: "Android auto-backup can exfiltrate SQLCipher DB to Google Drive in plaintext",
        severity: "high",
        category: "Android",
        filePatterns: ["**/AndroidManifest.xml"],
        badPatterns: [
            { pattern: /android:allowBackup="true"/, message: "Auto-backup enabled — encrypted DB may be exfiltrated" },
        ],
    },
    {
        id: "AND-004",
        name: "SQLCipher key from Keystore without StrongBox",
        description: "SQLCipher key should use StrongBox-backed Keystore when available (hardware isolation)",
        severity: "medium",
        category: "Android",
        filePatterns: ["**/*.kt", "**/*.java"],
        badPatterns: [
            { pattern: /KeyGenParameterSpec[\s\S]{0,500}(?!setIsStrongBoxBacked).*\.build\(\)/, message: "KeyGenParameterSpec without StrongBox backing" },
        ],
    },
    {
        id: "AND-005",
        name: "WebView JavaScript enabled",
        description: "WebView with JS enabled can be exploited for XSS / code execution",
        severity: "medium",
        category: "Android",
        filePatterns: ["**/*.kt", "**/*.java"],
        badPatterns: [
            { pattern: /javaScriptEnabled\s*=\s*true|setJavaScriptEnabled\(true\)/, message: "WebView JavaScript enabled — XSS risk" },
        ],
    },
    {
        id: "AND-006",
        name: "Screenshot not blocked in sensitive screens",
        description: "Chat and PIN screens should set FLAG_SECURE to prevent screenshots/screen recording",
        severity: "low",
        category: "Android",
        filePatterns: ["**/*.kt", "**/*.java"],
        requiredPatterns: [
            { pattern: /FLAG_SECURE/, message: "No FLAG_SECURE found — sensitive screens can be screenshotted", filePattern: "**/*Activity*" },
        ],
    },
];
// ─── Rust Backend ───────────────────────────────────────────────
export const backendRules = [
    {
        id: "SRV-001",
        name: "Missing rate limiting on public endpoint",
        description: "Public-facing endpoints that modify data must have rate limiting",
        severity: "medium",
        category: "Backend",
        filePatterns: ["**/handlers/*.rs"],
        badPatterns: [
            { pattern: /async fn (?:register|login|send_sealed|create|upload)\w*\([^)]*\)[^{]*\{(?![\s\S]{0,300}rate_limiter)/, message: "Public write endpoint without rate limiting" },
        ],
    },
    {
        id: "SRV-002",
        name: "DashMap Ref held across .await",
        description: "Holding a DashMap Ref across an await point can deadlock",
        severity: "high",
        category: "Backend",
        filePatterns: ["**/*.rs"],
        badPatterns: [
            { pattern: /\.get\(&[\w]+\)[\s\S]{0,100}\.await(?![\s\S]{0,20}\.clone\(\))/, message: "DashMap Ref possibly held across .await — clone before awaiting" },
        ],
    },
    {
        id: "SRV-003",
        name: "SQL injection via string interpolation",
        description: "SQL queries must use parameterized queries, not string interpolation",
        severity: "critical",
        category: "Backend",
        filePatterns: ["**/*.rs"],
        badPatterns: [
            { pattern: /format!\(.*(?:SELECT|INSERT|UPDATE|DELETE).*\{/, message: "SQL query built with format! — use parameterized queries" },
            { pattern: /&format!\(".*(?:SELECT|INSERT|UPDATE|DELETE)/, message: "SQL query built with format!" },
        ],
    },
    {
        id: "SRV-004",
        name: "Missing auth middleware on route",
        description: "API routes handling user data must require authentication",
        severity: "high",
        category: "Backend",
        filePatterns: ["**/*.rs"],
        badPatterns: [
            { pattern: /\.route\("[^"]*(?:message|contact|vault|profile|session)[^"]*",\s*(?:get|post|put|delete)\(\w+\)\)(?![\s\S]{0,100}AuthUser)/, message: "Route handling sensitive data may lack auth middleware" },
        ],
    },
    {
        id: "SRV-005",
        name: "Secrets in error response",
        description: "Error responses must not leak internal state, stack traces, or secrets",
        severity: "medium",
        category: "Backend",
        filePatterns: ["**/*.rs"],
        badPatterns: [
            { pattern: /AppError::Internal\(format!\(.*(?:password|key|secret|token)/, message: "Error response may leak secrets" },
        ],
    },
    {
        id: "SRV-006",
        name: "CORS allows wildcard origin",
        description: "CORS must not allow all origins — limits CSRF protection",
        severity: "high",
        category: "Backend",
        filePatterns: ["**/*.rs"],
        badPatterns: [
            { pattern: /allow_origin\(.*Any|AllowOrigin::any\(\)|"\*"/, message: "CORS allows wildcard origin" },
        ],
    },
    {
        id: "SRV-007",
        name: "Unsafe Rust block outside FFI",
        description: "Unsafe blocks outside known FFI bindings need manual review",
        severity: "medium",
        category: "Backend",
        filePatterns: ["**/handlers/*.rs", "**/services/*.rs", "**/middleware/*.rs", "**/db/*.rs"],
        badPatterns: [
            { pattern: /unsafe\s*\{/, message: "Unsafe block in application code — verify memory safety" },
        ],
    },
];
export const allRules = [
    ...e2eRules,
    ...webrtcRules,
    ...messengerRules,
    ...androidRules,
    ...backendRules,
];
