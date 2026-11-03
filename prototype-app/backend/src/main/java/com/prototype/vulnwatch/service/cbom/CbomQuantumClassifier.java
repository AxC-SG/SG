package com.prototype.vulnwatch.service.cbom;

import com.prototype.vulnwatch.domain.CbomAssetType;
import com.prototype.vulnwatch.domain.CbomComponent;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Post-quantum readiness of one cryptographic asset. Pure and shared: the PQC readiness counts and
 * the CBOM-QUANTUM-VULNERABLE rule use the same algorithm lists, so a card and a finding never
 * disagree about whether an algorithm is quantum-vulnerable.
 *
 * <p>An asset is classified from what it declares (primitive, name, parameter set, curve,
 * certificate signature algorithm, key-material type). Protocols and key material usually point at
 * the algorithm they use instead of naming it, so an asset that is not decided by its own fields
 * takes the outcome of the assets it uses (declared relationships), worst first. Anything still
 * undecided is UNKNOWN; nothing is guessed.
 */
public final class CbomQuantumClassifier {

    public enum Readiness { QUANTUM_VULNERABLE, CLASSICALLY_WEAK, PQC_READY, QUANTUM_SAFE, UNKNOWN }

    public record Result(Readiness readiness, String reason) { }

    /** Algorithm primitives the CBOM-QUANTUM-VULNERABLE rule flags (normalised primitive, exact match). */
    public static final Set<String> QUANTUM_VULNERABLE_PRIMITIVES = Set.of(
            "rsa", "dsa", "ecdsa", "ecdh", "ecdhe", "dh", "dhe", "ffdhe", "diffie-hellman", "ecc", "ecies",
            "ed25519", "ed448", "eddsa", "x25519", "x448", "elgamal");

    private static final List<String> PQC = List.of("mlkem", "mldsa", "slhdsa", "kyber", "dilithium", "sphincs",
            "falcon", "fndsa", "xmss", "frodo", "ntru", "hqc", "mceliece");
    /** Classical halves of hybrid names written as one word (X25519MLKEM768, SecP256r1MLKEM768). */
    private static final List<String> HYBRID_CLASSICAL = List.of("x25519", "x448", "secp256", "secp384", "p256", "p384",
            "ecdh", "ecdsa", "ed25519", "ed448", "rsa");
    private static final Set<String> WEAK_TOKENS = Set.of("md5", "md4", "md2", "sha1", "sha-1", "des", "3des", "tripledes",
            "desede", "rc4", "rc2", "arcfour");
    private static final Set<String> VULNERABLE_TOKENS = Set.of("rsa", "dsa", "ecdsa", "ecdh", "ecdhe", "ecc", "ecies",
            "dh", "dhe", "ffdhe", "ed25519", "ed448", "eddsa", "x25519", "x448", "elgamal", "curve25519", "curve448",
            "secp256r1", "secp384r1", "secp521r1", "secp256k1", "prime256v1", "p256", "p384", "p521", "brainpool",
            "rs256", "rs384", "rs512", "ps256", "ps384", "ps512", "es256", "es384", "es512");
    private static final Set<String> SYMMETRIC_TOKENS = Set.of("aes", "chacha20", "xchacha20", "camellia", "aria",
            "sm4", "twofish", "serpent");
    private static final Set<String> SAFE_TOKENS = Set.of("sha224", "sha256", "sha384", "sha512", "sha3", "shake128",
            "shake256", "blake2", "blake2b", "blake2s", "blake3", "hmac", "cmac", "gmac", "kmac", "poly1305", "hs256",
            "hs384", "hs512", "bcrypt", "scrypt", "argon2", "argon2id", "pbkdf2", "hkdf", "drbg", "ctrdrbg", "hmacdrbg");
    private static final Set<String> SAFE_PRIMITIVES = Set.of("ae", "block-cipher", "stream-cipher", "hash", "mac",
            "kdf", "drbg", "xof");
    /** Key-material types that are not asymmetric keys, so Shor's algorithm does not apply to them. */
    private static final Set<String> SYMMETRIC_MATERIAL = Set.of("secret-key", "shared-secret", "password",
            "credential", "token", "seed", "tag", "nonce", "salt", "initialization-vector", "iv", "digest", "hash");
    private static final Pattern BITS = Pattern.compile("(?<![0-9])(64|80|96|112|128|192|256)(?![0-9])");

    private CbomQuantumClassifier() { }

    public static boolean isQuantumVulnerablePrimitive(String primitive) {
        return primitive != null && QUANTUM_VULNERABLE_PRIMITIVES.contains(primitive.trim().toLowerCase(Locale.ROOT));
    }

    /** Classification from the asset's own declared fields only. */
    public static Result classifyOwn(CbomComponent c) {
        String text = String.join(" ", nz(c.getPrimitive()), nz(c.getName()), nz(c.getParameterSetIdentifier()),
                nz(c.getCurve()), nz(c.getSignatureAlgorithm())).toLowerCase(Locale.ROOT);
        String collapsed = text.replaceAll("[^a-z0-9]", "");
        Set<String> tokens = new HashSet<>(Arrays.asList(text.replaceAll("[^a-z0-9]+", " ").trim().split(" ")));
        tokens.addAll(Arrays.asList(text.replaceAll("[^a-z0-9-]+", " ").trim().split(" ")));
        String primitive = nz(c.getPrimitive()).trim().toLowerCase(Locale.ROOT);

        for (String marker : PQC) {
            if (collapsed.contains(marker)) {
                boolean hybrid = hasAny(tokens, VULNERABLE_TOKENS)
                        || HYBRID_CLASSICAL.stream().anyMatch(classical -> collapsed.replace(marker, "").contains(classical));
                return new Result(Readiness.PQC_READY, hybrid
                        ? "Hybrid post-quantum scheme (" + marker.toUpperCase(Locale.ROOT) + " with a classical algorithm)"
                        : "Post-quantum algorithm (" + marker.toUpperCase(Locale.ROOT) + ")");
            }
        }
        // Certificate signature names are one word (sha256WithRSAEncryption), so match inside them.
        String signature = nz(c.getSignatureAlgorithm()).toLowerCase(Locale.ROOT);
        String weak = firstOf(tokens, collapsed, WEAK_TOKENS);
        if (weak == null) weak = signatureMatch(signature, SIGNATURE_WEAK);
        if (weak != null) {
            return new Result(Readiness.CLASSICALLY_WEAK, weak.toUpperCase(Locale.ROOT)
                    + " is already broken or deprecated today; replace it regardless of quantum risk");
        }
        String vulnerable = firstOf(tokens, collapsed, VULNERABLE_TOKENS);
        if (vulnerable == null) vulnerable = signatureMatch(signature, SIGNATURE_VULNERABLE);
        if (vulnerable != null || isQuantumVulnerablePrimitive(primitive) || !nz(c.getCurve()).isBlank()) {
            String which = vulnerable != null ? vulnerable.toUpperCase(Locale.ROOT)
                    : !nz(c.getCurve()).isBlank() ? "Elliptic-curve (" + c.getCurve() + ")" : primitive.toUpperCase(Locale.ROOT);
            return new Result(Readiness.QUANTUM_VULNERABLE, which
                    + " is broken by Shor's algorithm on a cryptographically relevant quantum computer; plan migration to ML-KEM / ML-DSA");
        }
        String symmetric = firstOf(tokens, collapsed, SYMMETRIC_TOKENS);
        if (symmetric != null || Set.of("ae", "block-cipher", "stream-cipher").contains(primitive)) {
            Integer bits = symmetricBits(c, text);
            if (bits != null && bits < 128) {
                return new Result(Readiness.CLASSICALLY_WEAK, bits + "-bit symmetric keys are too short today and under quantum search");
            }
            if (bits != null && bits < 256) {
                return new Result(Readiness.QUANTUM_SAFE, (symmetric == null ? "Symmetric cipher" : symmetric.toUpperCase(Locale.ROOT))
                        + "-" + bits + " remains acceptable against quantum attack (Grover halves its strength); prefer 256-bit keys for long-lived data");
            }
            return new Result(Readiness.QUANTUM_SAFE, (symmetric == null ? "Symmetric cipher" : symmetric.toUpperCase(Locale.ROOT))
                    + (bits == null ? "" : "-" + bits) + " is not meaningfully weakened by quantum computers");
        }
        String safe = firstOf(tokens, collapsed, SAFE_TOKENS);
        if (safe != null || SAFE_PRIMITIVES.contains(primitive)) {
            return new Result(Readiness.QUANTUM_SAFE, (safe == null ? primitive.toUpperCase(Locale.ROOT) : safe.toUpperCase(Locale.ROOT))
                    + " (hash, MAC or key derivation) is not meaningfully weakened by quantum computers");
        }
        if (c.getAssetType() == CbomAssetType.RELATED_CRYPTO_MATERIAL
                && SYMMETRIC_MATERIAL.contains(nz(c.getComponentType()).trim().toLowerCase(Locale.ROOT))) {
            return new Result(Readiness.QUANTUM_SAFE, "Symmetric " + c.getComponentType() + " (not an asymmetric key); quantum computers do not break it");
        }
        return new Result(Readiness.UNKNOWN, unknownReason(c));
    }

    /**
     * Classification that also follows the algorithms an asset uses. {@code uses} maps a component id
     * to the ids it depends on or uses; {@code byId} resolves them. Worst outcome wins.
     */
    public static Result classify(CbomComponent c, Map<UUID, List<UUID>> uses, Map<UUID, CbomComponent> byId) {
        return classify(c, uses, byId, new HashSet<>(), 0);
    }

    private static Result classify(CbomComponent c, Map<UUID, List<UUID>> uses, Map<UUID, CbomComponent> byId, Set<UUID> seen, int depth) {
        Result own = classifyOwn(c);
        if (own.readiness() != Readiness.UNKNOWN || depth >= 3 || c.getId() == null || !seen.add(c.getId())) return own;
        Result worst = null;
        boolean allDecided = true;
        for (UUID target : uses.getOrDefault(c.getId(), List.of())) {
            CbomComponent next = byId.get(target);
            if (next == null) continue;
            Result result = classify(next, uses, byId, seen, depth + 1);
            if (result.readiness() == Readiness.UNKNOWN) { allDecided = false; continue; }
            if (worst == null || rank(result.readiness()) < rank(worst.readiness())) {
                worst = new Result(result.readiness(), "Uses " + next.getName() + ": " + result.reason());
            }
        }
        if (worst == null) return own;
        // A safe result only stands when every algorithm the asset uses is decided.
        if (worst.readiness() == Readiness.QUANTUM_SAFE && !allDecided) return own;
        return worst;
    }

    private static int rank(Readiness readiness) {
        return switch (readiness) {
            case QUANTUM_VULNERABLE -> 0;
            case CLASSICALLY_WEAK -> 1;
            case PQC_READY -> 2;
            case QUANTUM_SAFE -> 3;
            case UNKNOWN -> 4;
        };
    }

    /** Declared key size, else the largest key-size number in the name or parameter set (AES-256-GCM -> 256). */
    private static Integer symmetricBits(CbomComponent c, String text) {
        if (c.getKeySize() != null && c.getKeySize() > 0) return c.getKeySize();
        Matcher matcher = BITS.matcher(text);
        Integer best = null;
        while (matcher.find()) {
            int value = Integer.parseInt(matcher.group(1));
            best = best == null ? value : Math.max(best, value);
        }
        return best;
    }

    private static final Pattern SIGNATURE_WEAK = Pattern.compile("(md5|md2|sha1(?![0-9]))");
    private static final Pattern SIGNATURE_VULNERABLE = Pattern.compile("(ecdsa|rsa|dsa|ed25519|ed448)");

    private static String signatureMatch(String signature, Pattern pattern) {
        if (signature.isBlank()) return null;
        Matcher matcher = pattern.matcher(signature.replaceAll("[^a-z0-9]", ""));
        return matcher.find() ? matcher.group(1) : null;
    }

    private static String unknownReason(CbomComponent c) {
        return switch (c.getAssetType() == null ? CbomAssetType.UNKNOWN : c.getAssetType()) {
            case PROTOCOL -> "The protocol declares no cipher suites or algorithm references, so its key exchange cannot be judged";
            case RELATED_CRYPTO_MATERIAL -> "The key material declares no algorithm it is used with";
            case CERTIFICATE -> "The certificate declares no signature algorithm";
            default -> "The CBOM does not declare a recognised algorithm for this asset";
        };
    }

    private static String firstOf(Set<String> tokens, String collapsed, Set<String> candidates) {
        for (String token : tokens) if (candidates.contains(token)) return token;
        for (String candidate : candidates) if (candidate.length() >= 5 && collapsed.contains(candidate)) return candidate;
        return null;
    }

    private static boolean hasAny(Set<String> tokens, Set<String> candidates) {
        for (String token : tokens) if (candidates.contains(token)) return true;
        return false;
    }

    private static String nz(String value) { return value == null ? "" : value; }
}
