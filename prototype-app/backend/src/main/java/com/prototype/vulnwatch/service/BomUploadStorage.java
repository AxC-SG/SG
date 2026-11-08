package com.prototype.vulnwatch.service;

import jakarta.annotation.PreDestroy;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.ChecksumMode;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.ServerSideEncryption;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.PutObjectPresignRequest;

@Component
class BomUploadStorage {
    private final String bucket;
    private final S3Client client;
    private final S3Presigner presigner;

    @org.springframework.beans.factory.annotation.Autowired
    BomUploadStorage(@Value("${app.bom.uploads.bucket:}") String bucket,
                     @Value("${app.bom.uploads.region:us-east-1}") String region) {
        this(bucket, bucket.isBlank() ? null : S3Client.builder().region(Region.of(region))
                        .overrideConfiguration(builder -> builder.apiCallTimeout(Duration.ofSeconds(60))).build(),
                bucket.isBlank() ? null : S3Presigner.builder().region(Region.of(region)).build());
    }

    BomUploadStorage(String bucket, S3Client client, S3Presigner presigner) {
        this.bucket = bucket;
        this.client = client;
        this.presigner = presigner;
    }

    void requireConfigured() {
        if (!configured()) {
            throw new IllegalStateException("BOM upload storage is unavailable");
        }
    }

    boolean configured() {
        return client != null && presigner != null;
    }

    SignedPut sign(String key, long size, String sha256, Duration ttl) {
        requireConfigured();
        var signed = presigner.presignPutObject(PutObjectPresignRequest.builder()
                .signatureDuration(ttl)
                .putObjectRequest(PutObjectRequest.builder().bucket(bucket).key(key)
                        .contentLength(size).checksumSHA256(sha256).ifNoneMatch("*").build())
                .build());
        Map<String, String> browserHeaders = new LinkedHashMap<>();
        signed.signedHeaders().forEach((name, values) -> {
            if (!"host".equalsIgnoreCase(name) && !"content-length".equalsIgnoreCase(name)) {
                browserHeaders.put(name, String.join(",", values));
            }
        });
        String query = signed.url().getQuery().toLowerCase(Locale.ROOT);
        if (!signed.signedHeaders().containsKey("content-length")
                || !signed.signedHeaders().containsKey("if-none-match")
                || (!signed.signedHeaders().containsKey("x-amz-checksum-sha256")
                    && !query.contains("x-amz-checksum-sha256="))) {
            throw new IllegalStateException("BOM upload signature does not bind all required conditions");
        }
        return new SignedPut(signed.url().toString(), Map.copyOf(browserHeaders));
    }

    String verifiedVersion(String key, long size, String sha256) {
        requireConfigured();
        var head = client.headObject(HeadObjectRequest.builder().bucket(bucket).key(key)
                .checksumMode(ChecksumMode.ENABLED).build());
        if (head.versionId() == null || "null".equals(head.versionId())
                || !Long.valueOf(size).equals(head.contentLength()) || !sha256.equals(head.checksumSHA256())
                || head.serverSideEncryption() != ServerSideEncryption.AWS_KMS) {
            throw new IllegalArgumentException("Uploaded object does not match the reserved version, size or checksum");
        }
        return head.versionId();
    }

    byte[] read(String key, String version, int size, String sha256) throws IOException {
        requireConfigured();
        var request = GetObjectRequest.builder().bucket(bucket).key(key).versionId(version).build();
        try (var stream = client.getObject(request)) {
            var response = stream.response();
            if (!version.equals(response.versionId()) || !Long.valueOf(size).equals(response.contentLength())) {
                stream.abort();
                throw new IOException("Stored BOM version or length changed");
            }
            byte[] bytes = new byte[size];
            long started = System.nanoTime();
            for (int offset = 0; offset < size; ) {
                int count = stream.read(bytes, offset, Math.min(size - offset, 64 * 1024));
                if (count < 0 || System.nanoTime() - started > Duration.ofSeconds(60).toNanos()) {
                    stream.abort();
                    throw new IOException("Stored BOM ended early or exceeded its download deadline");
                }
                offset += count;
            }
            if (stream.read() != -1) {
                stream.abort();
                throw new IOException("Stored BOM exceeds its reserved length");
            }
            if (!sha256.equals(checksum(bytes))) {
                throw new IOException("Stored BOM checksum does not match");
            }
            return bytes;
        } catch (S3Exception failure) {
            throw new IOException("Stored BOM could not be read", failure);
        }
    }

    private static String checksum(byte[] bytes) {
        try {
            return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    @PreDestroy
    void close() {
        if (presigner != null) {
            presigner.close();
        }
        if (client != null) {
            client.close();
        }
    }

    record SignedPut(String url, Map<String, String> headers) { }
}
