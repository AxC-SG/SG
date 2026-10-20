package com.prototype.vulnwatch.client;

import com.prototype.vulnwatch.domain.AwsAuthType;
import com.prototype.vulnwatch.domain.AwsDiscoveryConfig;
import com.prototype.vulnwatch.domain.AwsDiscoveryTarget;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;

/**
 * Factory that builds an AWS SDK v2 {@link AwsCredentialsProvider} from the
 * {@link AwsDiscoveryConfig}. This is the ONLY class that reads
 * {@code credentialSecret} directly — it must never log or expose the value.
 */
public final class AwsCredentialProvider {

    private AwsCredentialProvider() {}

    /**
     * Build a credentials provider for the given config.
     * <p>
     * The provider is created fresh on every call (not cached) so that
     * rotated access keys and short-lived AssumeRole tokens are always current.
     */
    public static AwsCredentialsProvider from(AwsDiscoveryConfig config) {
        AwsCustomerBinding.validate(config.getTenant() == null ? null : config.getTenant().getId(), config.getAwsAccountId(), config.getCrossAccountRoleArn(),
                config.getExternalId(), config.getCredentialBindingVersion());
        return buildAssumeRoleProvider(config);
    }

    public static AwsCredentialsProvider from(AwsDiscoveryConfig config, AwsDiscoveryTarget target) {
        if (target == null) return from(config);
        if (config.getTenant() == null || target.getTenant() == null
                || !config.getTenant().getId().equals(target.getTenant().getId())
                || target.getConfig() == null || !config.getTenant().getId().equals(target.getConfig().getTenant().getId())) {
            throw new IllegalArgumentException("AWS target does not belong to the customer connector");
        }
        AwsCustomerBinding.validate(target.getTenant().getId(), target.getAccountId(), target.getRoleArn(),
                target.getExternalId(), target.getCredentialBindingVersion());
        return buildAssumeRoleProvider(
                target.getRoleArn(),
                target.getExternalId(),
                config.getAccessKeyId(),
                config.getCredentialSecret(),
                "vulnwatch-aws-discovery-" + sessionSuffix(target.getAccountId())
        );
    }

    private static AwsCredentialsProvider buildAccessKeyProvider(AwsDiscoveryConfig config) {
        String keyId = config.getAccessKeyId();
        String secret = config.getCredentialSecret();
        if (!hasText(keyId) || !hasText(secret)) {
            throw new IllegalStateException(
                    "AWS_DISCOVERY: ACCESS_KEY auth requires both accessKeyId and credentialSecret to be configured.");
        }
        // secret is used here and goes no further
        return StaticCredentialsProvider.create(AwsBasicCredentials.create(keyId.trim(), secret.trim()));
    }

    private static AwsCredentialsProvider buildAssumeRoleProvider(AwsDiscoveryConfig config) {
        String roleArn = config.getCrossAccountRoleArn();
        if (!hasText(roleArn)) {
            throw new IllegalStateException(
                    "AWS_DISCOVERY: CROSS_ACCOUNT_ROLE auth requires crossAccountRoleArn to be configured.");
        }
        return buildAssumeRoleProvider(
                roleArn,
                config.getExternalId(),
                config.getAccessKeyId(),
                config.getCredentialSecret(),
                "vulnwatch-aws-discovery"
        );
    }

    private static AwsCredentialsProvider buildAssumeRoleProvider(
            String roleArn,
            String externalId,
            String accessKeyId,
            String credentialSecret,
            String roleSessionName
    ) {
        AssumeRoleRequest.Builder requestBuilder = AssumeRoleRequest.builder()
                .roleArn(roleArn.trim())
                .roleSessionName(roleSessionName);
        requestBuilder.externalId(externalId.trim());
        // If access key credentials are provided, use them as the base identity for STS.
        // This supports the pattern: long-lived IAM user keys → AssumeRole → short-lived tokens.
        // Without explicit credentials, the STS client falls back to the default chain
        // (e.g. root account), which AWS prohibits from assuming roles.
        StsClient stsClient;
        if (hasText(accessKeyId) && hasText(credentialSecret)) {
            stsClient = StsClient.builder()
                    .region(Region.US_EAST_1)
                    .credentialsProvider(StaticCredentialsProvider.create(
                            AwsBasicCredentials.create(
                                    accessKeyId.trim(),
                                    credentialSecret.trim())))
                    .build();
        } else {
            String profile = System.getenv("AWS_PROFILE");
            AwsCredentialsProvider base = hasText(profile)
                    ? ProfileCredentialsProvider.create(profile.trim()) : DefaultCredentialsProvider.create();
            stsClient = StsClient.builder()
                    .region(Region.US_EAST_1)
                    .credentialsProvider(base)
                    .build();
        }
        StsAssumeRoleCredentialsProvider assumed = StsAssumeRoleCredentialsProvider.builder()
                .stsClient(stsClient)
                .refreshRequest(requestBuilder.build())
                .build();
        return assumed;
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private static String sessionSuffix(String value) {
        if (!hasText(value)) {
            return "target";
        }
        return value.replaceAll("[^A-Za-z0-9+=,.@-]", "-");
    }
}
