package com.prototype.vulnwatch.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ServerSideEncryption;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;

class BomUploadStorageTest {
    private static final String SHA256 = "zadF0MgpQ6R/vPDzwdEGdn0PFllM0VmEiLuiL0OZyhA=";
    private final S3Client client = mock(S3Client.class);

    @Test
    void presignedPutBindsSizeChecksumAndCreateOnlyCondition() {
        try (var presigner = presigner()) {
            var storage = new BomUploadStorage("scoutgrid-test-imports", client, presigner);
            var signed = storage.sign("tenant-id/upload-id", 21, SHA256, Duration.ofMinutes(5));

            URI url = URI.create(signed.url());
            assertThat(url.getPath()).endsWith("/tenant-id/upload-id");
            assertThat(url.getQuery()).contains("X-Amz-Expires=300", "content-length", "if-none-match");
            assertThat(signed.headers()).containsEntry("if-none-match", "*").doesNotContainKeys("host", "content-length");
            assertThat(signed.headers().containsValue(SHA256) || url.getQuery().contains("x-amz-checksum-sha256="))
                    .isTrue();
        }
    }

    @Test
    void finalizationRequiresAnEncryptedImmutableVersionAndMatchingChecksum() {
        try (var presigner = presigner()) {
            var storage = new BomUploadStorage("scoutgrid-test-imports", client, presigner);
            var head = HeadObjectResponse.builder().versionId("version-1").contentLength(21L)
                    .checksumSHA256(SHA256).serverSideEncryption(ServerSideEncryption.AWS_KMS).build();
            when(client.headObject(any(HeadObjectRequest.class))).thenReturn(head, head.toBuilder().versionId("null").build(),
                    head.toBuilder().checksumSHA256("invalid").build(), head.toBuilder().contentLength(22L).build());

            assertThat(storage.verifiedVersion("tenant-id/upload-id", 21, SHA256)).isEqualTo("version-1");
            for (int attempt = 0; attempt < 3; attempt++) {
                assertThatThrownBy(() -> storage.verifiedVersion("tenant-id/upload-id", 21, SHA256))
                        .isInstanceOf(IllegalArgumentException.class);
            }
        }
    }

    private static S3Presigner presigner() {
        return S3Presigner.builder().region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("test-access", "test-secret")))
                .build();
    }
}
