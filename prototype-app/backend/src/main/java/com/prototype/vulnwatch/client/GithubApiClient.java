package com.prototype.vulnwatch.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundFailureContext;
import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

@Component
public class GithubApiClient {

    public record GithubSbomResponse(
            byte[] payload,
            Integer statusCode,
            String contentType,
            long contentLength,
            String endpoint
    ) {
    }

    public record GithubRepositoryRef(
            String owner,
            String repo,
            String fullName,
            String htmlUrl,
            boolean privateRepo,
            String defaultBranch
    ) {
    }

    public record GithubAttestedSbomResponse(
            byte[] payload,
            Integer statusCode,
            String contentType,
            long contentLength,
            String endpoint,
            String predicateType,
            String subjectName,
            int attestationCount
    ) {
    }

    public record GithubContainerPackageRef(
            String owner,
            String packageName,
            String imageRepository
    ) {
    }

    public record GithubContainerImageVersionRef(
            String owner,
            String packageName,
            String imageRepository,
            String digest,
            List<String> tags
    ) {
    }

    public record GithubAttestationLookup(
            String imageRepository,
            String subjectDigest
    ) {
    }

    public record GithubRepoFileRef(
            String path,
            String sha,
            long size
    ) {
    }

    private final ObjectMapper objectMapper;
    private final GithubTokenProvider githubTokenProvider;
    private final OutboundHttpClient outboundHttpClient;
    private final OutboundPolicyFactory outboundPolicyFactory;

    @Value("${app.github.base-url:https://api.github.com}")
    private String baseUrl;

    @Value("${app.github.allowlist-enabled:true}")
    private boolean allowlistEnabled;

    @Value("${app.github.allowed-repos:}")
    private String allowedReposCsv;

    @Value("${app.github.allowed-packages:}")
    private String allowedPackagesCsv;

    @Value("${app.github.max-retries:4}")
    private int maxRetries;

    @Value("${app.github.retry-base-backoff-ms:1000}")
    private long retryBaseBackoffMs;

    @Value("${app.github.max-pages-per-collection:250}")
    private int maxPagesPerCollection;

    @Value("${app.github.min-rate-limit-remaining:25}")
    private int minRateLimitRemaining;

    private Set<String> allowedRepos = Set.of();
    private Set<String> allowedPackages = Set.of();

    public GithubApiClient(
            ObjectMapper objectMapper,
            GithubTokenProvider githubTokenProvider,
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory
    ) {
        this.objectMapper = objectMapper;
        this.githubTokenProvider = githubTokenProvider;
        this.outboundHttpClient = outboundHttpClient;
        this.outboundPolicyFactory = outboundPolicyFactory;
    }

    @PostConstruct
    public void init() {
        this.allowedRepos = parseAllowedRepos();
        this.allowedPackages = parseAllowedPackages();
    }

    public boolean hasToken() {
        return githubTokenProvider.hasToken();
    }

    public GithubSbomResponse fetchGeneratedSbom(String owner, String repo) throws IOException {
        String normalizedOwner = normalize(owner);
        String normalizedRepo = normalize(repo);
        assertAllowed(normalizedOwner, normalizedRepo);

        String endpoint = buildGeneratedSbomEndpoint(normalizedOwner, normalizedRepo);
        ResponseEntity<byte[]> response = exchangeWithRetry(endpoint, byte[].class, "GitHub SBOM API");
        byte[] payload = response.getBody();
        if (payload == null || payload.length == 0) {
            throw new IOException("GitHub generated SBOM response was empty");
        }
        long contentLength = response.getHeaders().getContentLength() >= 0
                ? response.getHeaders().getContentLength()
                : payload.length;
        return new GithubSbomResponse(
                payload,
                response.getStatusCode().value(),
                response.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE),
                contentLength,
                endpoint
        );
    }

    public List<GithubRepoFileRef> listRepoBomFiles(String owner, String repo, com.prototype.vulnwatch.domain.BomType bomType) throws IOException {
        String normalizedOwner = normalize(owner);
        String normalizedRepo = normalize(repo);
        assertAllowed(normalizedOwner, normalizedRepo);

        String defaultBranch = fetchDefaultBranch(normalizedOwner, normalizedRepo);
        String endpoint = UriComponentsBuilder.fromUriString(baseUrl)
                .pathSegment("repos", normalizedOwner, normalizedRepo, "git", "trees", defaultBranch)
                .queryParam("recursive", "1")
                .build()
                .toUriString();

        ResponseEntity<String> response = exchangeWithRetry(endpoint, String.class, "GitHub repo tree API");
        JsonNode root;
        try {
            root = objectMapper.readTree(response.getBody());
        } catch (Exception e) {
            throw new IOException("Failed to parse GitHub repo tree response", e);
        }
        JsonNode tree = root.path("tree");
        if (!tree.isArray()) {
            return List.of();
        }

        List<String> suffixes = bomFileSuffixes(bomType);
        List<GithubRepoFileRef> matches = new ArrayList<>();
        for (JsonNode entry : tree) {
            if (!"blob".equals(entry.path("type").asText(""))) continue;
            String filePath = entry.path("path").asText("");
            if (filePath.isBlank()) continue;
            String filename = filePath.contains("/") ? filePath.substring(filePath.lastIndexOf('/') + 1) : filePath;
            String lowerFilename = filename.toLowerCase(java.util.Locale.ROOT);
            boolean matched = suffixes.stream().anyMatch(lowerFilename::endsWith);
            if (matched) {
                matches.add(new GithubRepoFileRef(filePath, entry.path("sha").asText(null), entry.path("size").asLong(0)));
            }
        }
        return matches;
    }

    public byte[] fetchRepoFileContent(String owner, String repo, String filePath) throws IOException {
        String normalizedOwner = normalize(owner);
        String normalizedRepo = normalize(repo);
        assertAllowed(normalizedOwner, normalizedRepo);

        String endpoint = UriComponentsBuilder.fromUriString(baseUrl)
                .pathSegment("repos", normalizedOwner, normalizedRepo, "contents", filePath)
                .build()
                .toUriString();

        ResponseEntity<String> response = exchangeWithRetry(endpoint, String.class, "GitHub file content API");
        JsonNode root;
        try {
            root = objectMapper.readTree(response.getBody());
        } catch (Exception e) {
            throw new IOException("Failed to parse GitHub file content response", e);
        }
        String encoding = root.path("encoding").asText("");
        String encodedContent = root.path("content").asText("");
        if ("base64".equals(encoding)) {
            String cleaned = encodedContent.replaceAll("\\s+", "");
            return Base64.getDecoder().decode(cleaned);
        }
        throw new IOException("Unsupported file content encoding from GitHub: " + encoding);
    }

    private String fetchDefaultBranch(String owner, String repo) throws IOException {
        String endpoint = UriComponentsBuilder.fromUriString(baseUrl)
                .pathSegment("repos", owner, repo)
                .build()
                .toUriString();
        ResponseEntity<String> response = exchangeWithRetry(endpoint, String.class, "GitHub repo metadata API");
        JsonNode root;
        try {
            root = objectMapper.readTree(response.getBody());
        } catch (Exception e) {
            return "main";
        }
        String branch = root.path("default_branch").asText("main");
        return branch.isBlank() ? "main" : branch;
    }

    private List<String> bomFileSuffixes(com.prototype.vulnwatch.domain.BomType bomType) {
        return switch (bomType) {
            case CBOM -> List.of("cbom.json", "cbom.xml");
            case AI_BOM -> List.of("aibom.json", "aibom.xml", "ai-bom.json", "ai-bom.xml", "ml-bom.json", "ml-bom.xml");
            default -> List.of();
        };
    }

    public List<GithubRepositoryRef> listAccountRepositories(String account) throws IOException {
        String normalizedAccount = normalize(account);
        if (normalizedAccount.isBlank()) {
            throw new IOException("GitHub account owner is required");
        }
        Map<String, GithubRepositoryRef> merged = new LinkedHashMap<>();
        boolean orgNotFound = false;
        boolean userNotFound = false;

        try {
            for (GithubRepositoryRef repo : listRepositoriesByEndpoint(buildOrgReposEndpoint(normalizedAccount))) {
                if (isAllowed(repo.owner(), repo.repo())) {
                    merged.put(repo.owner() + "/" + repo.repo(), repo);
                }
            }
        } catch (GithubNotFoundException e) {
            orgNotFound = true;
        }

        try {
            for (GithubRepositoryRef repo : listRepositoriesByEndpoint(buildUserReposEndpoint(normalizedAccount))) {
                if (isAllowed(repo.owner(), repo.repo())) {
                    merged.put(repo.owner() + "/" + repo.repo(), repo);
                }
            }
        } catch (GithubNotFoundException e) {
            userNotFound = true;
        }

        if (merged.isEmpty() && orgNotFound && userNotFound) {
            throw new IOException("GitHub account was not found or is inaccessible: " + normalizedAccount);
        }
        return new ArrayList<>(merged.values());
    }

    public List<GithubContainerPackageRef> listContainerPackages(String account) throws IOException {
        String normalizedAccount = normalize(account);
        if (normalizedAccount.isBlank()) {
            throw new IOException("GitHub account owner is required");
        }
        Map<String, GithubContainerPackageRef> merged = new LinkedHashMap<>();
        boolean orgNotFound = false;
        boolean userNotFound = false;

        try {
            for (GithubContainerPackageRef pkg : listContainerPackagesByEndpoint(
                    normalizedAccount,
                    buildOrgPackagesEndpoint(normalizedAccount))) {
                merged.put(pkg.imageRepository(), pkg);
            }
        } catch (GithubNotFoundException e) {
            orgNotFound = true;
        }

        try {
            for (GithubContainerPackageRef pkg : listContainerPackagesByEndpoint(
                    normalizedAccount,
                    buildUserPackagesEndpoint(normalizedAccount))) {
                merged.put(pkg.imageRepository(), pkg);
            }
        } catch (GithubNotFoundException e) {
            userNotFound = true;
        }

        if (merged.isEmpty() && orgNotFound && userNotFound) {
            throw new IOException("GitHub account was not found or is inaccessible: " + normalizedAccount);
        }
        return new ArrayList<>(merged.values());
    }

    public List<GithubContainerImageVersionRef> listContainerImageVersions(
            String owner,
            String packageName
    ) throws IOException {
        String normalizedOwner = normalize(owner);
        String normalizedPackageName = normalize(packageName);
        if (normalizedOwner.isBlank()) {
            throw new IOException("GitHub account owner is required");
        }
        if (normalizedPackageName.isBlank()) {
            throw new IOException("GHCR package name is required");
        }

        try {
            return listContainerPackageVersionsByEndpoint(
                    normalizedOwner,
                    normalizedPackageName,
                    buildOrgPackageVersionsEndpoint(normalizedOwner, normalizedPackageName));
        } catch (GithubNotFoundException orgNotFound) {
            try {
                return listContainerPackageVersionsByEndpoint(
                        normalizedOwner,
                        normalizedPackageName,
                        buildUserPackageVersionsEndpoint(normalizedOwner, normalizedPackageName));
            } catch (GithubNotFoundException userNotFound) {
                throw new IOException("GHCR package was not found or is inaccessible: " + normalizedOwner + "/" + normalizedPackageName);
            }
        }
    }

    public GithubAttestedSbomResponse fetchAttestedSbom(
            String owner,
            String repo,
            String subjectDigest,
            String expectedImageRepository
    ) throws IOException {
        String normalizedOwner = normalize(owner);
        String normalizedRepo = normalize(repo);
        assertAllowed(normalizedOwner, normalizedRepo);

        String normalizedDigest = normalizeDigest(subjectDigest);
        if (normalizedDigest.isBlank()) {
            throw new IOException("GitHub attestation subject digest is required");
        }

        return fetchAttestedSbomFromEndpoint(
                normalizedDigest,
                expectedImageRepository,
                buildAttestationsEndpoint(normalizedOwner, normalizedRepo, normalizedDigest),
                "GitHub attestation API");
    }

    public GithubAttestedSbomResponse fetchAttestedSbomForOwner(
            String owner,
            String subjectDigest,
            String expectedImageRepository
    ) throws IOException {
        String normalizedOwner = normalize(owner);
        if (normalizedOwner.isBlank()) {
            throw new IOException("GitHub owner/account is required");
        }

        String normalizedDigest = normalizeDigest(subjectDigest);
        if (normalizedDigest.isBlank()) {
            throw new IOException("GitHub attestation subject digest is required");
        }

        try {
            return fetchAttestedSbomFromEndpoint(
                    normalizedDigest,
                    expectedImageRepository,
                    buildOrgOwnerAttestationsEndpoint(normalizedOwner, normalizedDigest),
                    "GitHub organization attestation API");
        } catch (GithubNotFoundException orgNotFound) {
            try {
                return fetchAttestedSbomFromEndpoint(
                        normalizedDigest,
                        expectedImageRepository,
                        buildUserOwnerAttestationsEndpoint(normalizedOwner, normalizedDigest),
                        "GitHub user attestation API");
            } catch (GithubNotFoundException userNotFound) {
                throw new IOException("GitHub account was not found or is inaccessible: " + normalizedOwner, userNotFound);
            }
        }
    }

    public Map<String, GithubAttestedSbomResponse> fetchAttestedSbomsForOwnerBulk(
            String owner,
            List<GithubAttestationLookup> lookups
    ) throws IOException {
        String normalizedOwner = normalize(owner);
        if (normalizedOwner.isBlank()) {
            throw new IOException("GitHub owner/account is required");
        }
        if (lookups == null || lookups.isEmpty()) {
            return Map.of();
        }

        List<GithubAttestationLookup> normalizedLookups = new ArrayList<>();
        Map<String, Set<String>> expectedRepositoriesByDigest = new LinkedHashMap<>();
        for (GithubAttestationLookup lookup : lookups) {
            if (lookup == null) {
                continue;
            }
            String imageRepository = normalizeContainerRepository(lookup.imageRepository());
            String subjectDigest = normalizeDigest(lookup.subjectDigest());
            if (imageRepository.isBlank() || subjectDigest.isBlank()) {
                continue;
            }
            normalizedLookups.add(new GithubAttestationLookup(imageRepository, subjectDigest));
            expectedRepositoriesByDigest.computeIfAbsent(subjectDigest, ignored -> new LinkedHashSet<>()).add(imageRepository);
        }
        if (normalizedLookups.isEmpty()) {
            return Map.of();
        }

        try {
            return fetchAttestedSbomsFromBulkEndpoint(
                    buildOrgOwnerBulkAttestationsEndpoint(normalizedOwner),
                    normalizedLookups,
                    expectedRepositoriesByDigest,
                    "GitHub organization attestation bulk API");
        } catch (GithubNotFoundException orgNotFound) {
            try {
                return fetchAttestedSbomsFromBulkEndpoint(
                        buildUserOwnerBulkAttestationsEndpoint(normalizedOwner),
                        normalizedLookups,
                        expectedRepositoriesByDigest,
                        "GitHub user attestation bulk API");
            } catch (GithubNotFoundException userNotFound) {
                throw new IOException("GitHub account was not found or is inaccessible: " + normalizedOwner, userNotFound);
            }
        }
    }

    public String buildGeneratedSbomEndpoint(String owner, String repo) {
        return UriComponentsBuilder.fromUriString(baseUrl)
                .pathSegment("repos", normalize(owner), normalize(repo), "dependency-graph", "sbom")
                .build()
                .toUriString();
    }

    public String buildAttestationsEndpoint(String owner, String repo, String subjectDigest) {
        return UriComponentsBuilder.fromUriString(baseUrl)
                .pathSegment("repos", normalize(owner), normalize(repo), "attestations", subjectDigest)
                .queryParam("predicate_type", "sbom")
                .build()
                .toUriString();
    }

    public String buildOrgOwnerAttestationsEndpoint(String owner, String subjectDigest) {
        return UriComponentsBuilder.fromUriString(baseUrl)
                .pathSegment("orgs", normalize(owner), "attestations", subjectDigest)
                .queryParam("predicate_type", "sbom")
                .build()
                .toUriString();
    }

    public String buildUserOwnerAttestationsEndpoint(String owner, String subjectDigest) {
        return UriComponentsBuilder.fromUriString(baseUrl)
                .pathSegment("users", normalize(owner), "attestations", subjectDigest)
                .queryParam("predicate_type", "sbom")
                .build()
                .toUriString();
    }

    public String buildOrgOwnerBulkAttestationsEndpoint(String owner) {
        return UriComponentsBuilder.fromUriString(baseUrl)
                .pathSegment("orgs", normalize(owner), "attestations", "bulk-list")
                .queryParam("predicate_type", "sbom")
                .build()
                .toUriString();
    }

    public String buildUserOwnerBulkAttestationsEndpoint(String owner) {
        return UriComponentsBuilder.fromUriString(baseUrl)
                .pathSegment("users", normalize(owner), "attestations", "bulk-list")
                .queryParam("predicate_type", "sbom")
                .build()
                .toUriString();
    }

    private void assertAllowed(String owner, String repo) throws IOException {
        if (!isAllowed(owner, repo)) {
            throw new IOException("GitHub repository is not allowlisted: " + owner + "/" + repo);
        }
    }

    private boolean isAllowed(String owner, String repo) {
        if (!allowlistEnabled) {
            return true;
        }
        if (allowedRepos.isEmpty()) {
            return true;
        }
        return allowedRepos.contains(owner + "/" + repo);
    }

    private boolean isContainerPackageAllowed(String owner, String packageName) {
        if (!allowlistEnabled) {
            return true;
        }
        if (allowedPackages.isEmpty()) {
            return true;
        }
        return allowedPackages.contains(owner + "/" + packageName);
    }

    private Set<String> parseAllowedRepos() {
        return parseAllowlistCsv(allowedReposCsv);
    }

    private Set<String> parseAllowedPackages() {
        return parseAllowlistCsv(allowedPackagesCsv);
    }

    private Set<String> parseAllowlistCsv(String csv) {
        if (csv == null || csv.isBlank()) {
            return Set.of();
        }
        Set<String> values = new HashSet<>();
        for (String value : csv.split(",")) {
            if (value == null || value.isBlank()) {
                continue;
            }
            String normalized = value.trim().toLowerCase(Locale.ROOT);
            if (!normalized.contains("/")) {
                continue;
            }
            values.add(normalized);
        }
        return values;
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private String buildOrgReposEndpoint(String account) {
        return UriComponentsBuilder.fromUriString(baseUrl)
                .pathSegment("orgs", account, "repos")
                .build()
                .toUriString();
    }

    private String buildUserReposEndpoint(String account) {
        return UriComponentsBuilder.fromUriString(baseUrl)
                .pathSegment("users", account, "repos")
                .build()
                .toUriString();
    }

    private String buildOrgPackagesEndpoint(String account) {
        return UriComponentsBuilder.fromUriString(baseUrl)
                .pathSegment("orgs", account, "packages")
                .build()
                .toUriString();
    }

    private String buildUserPackagesEndpoint(String account) {
        return UriComponentsBuilder.fromUriString(baseUrl)
                .pathSegment("users", account, "packages")
                .build()
                .toUriString();
    }

    private String buildOrgPackageVersionsEndpoint(String owner, String packageName) {
        return UriComponentsBuilder.fromUriString(baseUrl)
                .pathSegment("orgs", owner, "packages", "container", packageName, "versions")
                .build()
                .toUriString();
    }

    private String buildUserPackageVersionsEndpoint(String owner, String packageName) {
        return UriComponentsBuilder.fromUriString(baseUrl)
                .pathSegment("users", owner, "packages", "container", packageName, "versions")
                .build()
                .toUriString();
    }

    private String buildGhcrImageRepository(String owner, String packageName) {
        return "ghcr.io/" + normalize(owner) + "/" + normalize(packageName);
    }

    private List<GithubRepositoryRef> listRepositoriesByEndpoint(String endpointBase) throws IOException {
        List<GithubRepositoryRef> repositories = new ArrayList<>();
        for (int page = 1; page <= maxCollectionPages(); page++) {
            String endpoint = UriComponentsBuilder.fromUriString(endpointBase)
                    .queryParam("per_page", 100)
                    .queryParam("page", page)
                    .queryParam("type", "all")
                    .build()
                    .toUriString();
            ResponseEntity<String> response = exchangeWithRetry(endpoint, String.class, "GitHub repositories API");
            JsonNode root = parseArrayResponse(response.getBody(), "GitHub repository list");
            if (root.isEmpty()) {
                break;
            }
            for (JsonNode entry : root) {
                JsonNode ownerNode = entry.path("owner");
                String owner = normalize(ownerNode.path("login").asText(""));
                String repo = normalize(entry.path("name").asText(""));
                if (owner.isBlank() || repo.isBlank()) {
                    continue;
                }
                repositories.add(new GithubRepositoryRef(
                        owner,
                        repo,
                        entry.path("full_name").asText(owner + "/" + repo),
                        entry.path("html_url").asText(""),
                        entry.path("private").asBoolean(false),
                        entry.path("default_branch").asText("")));
            }
            if (root.size() < 100) {
                break;
            }
            ensureCanContinuePaging(response, "GitHub repositories API", page);
        }
        return repositories;
    }

    private List<GithubContainerPackageRef> listContainerPackagesByEndpoint(
            String owner,
            String endpointBase
    ) throws IOException {
        List<GithubContainerPackageRef> packages = new ArrayList<>();
        for (int page = 1; page <= maxCollectionPages(); page++) {
            String endpoint = UriComponentsBuilder.fromUriString(endpointBase)
                    .queryParam("package_type", "container")
                    .queryParam("per_page", 100)
                    .queryParam("page", page)
                    .build()
                    .toUriString();
            ResponseEntity<String> response = exchangeWithRetry(endpoint, String.class, "GitHub packages API");
            JsonNode root = parseArrayResponse(response.getBody(), "GitHub package list");
            if (root.isEmpty()) {
                break;
            }
            for (JsonNode entry : root) {
                String packageName = normalize(entry.path("name").asText(""));
                if (packageName.isBlank() || !isContainerPackageAllowed(owner, packageName)) {
                    continue;
                }
                packages.add(new GithubContainerPackageRef(
                        owner,
                        packageName,
                        buildGhcrImageRepository(owner, packageName)));
            }
            if (root.size() < 100) {
                break;
            }
            ensureCanContinuePaging(response, "GitHub packages API", page);
        }
        return packages;
    }

    private List<GithubContainerImageVersionRef> listContainerPackageVersionsByEndpoint(
            String owner,
            String packageName,
            String endpointBase
    ) throws IOException {
        List<GithubContainerImageVersionRef> versions = new ArrayList<>();
        for (int page = 1; page <= maxCollectionPages(); page++) {
            String endpoint = UriComponentsBuilder.fromUriString(endpointBase)
                    .queryParam("per_page", 100)
                    .queryParam("page", page)
                    .build()
                    .toUriString();
            ResponseEntity<String> response = exchangeWithRetry(endpoint, String.class, "GitHub package versions API");
            JsonNode root = parseArrayResponse(response.getBody(), "GitHub package versions list");
            if (root.isEmpty()) {
                break;
            }
            for (JsonNode entry : root) {
                String digest = extractContainerDigest(entry);
                if (digest.isBlank()) {
                    continue;
                }
                List<String> tags = extractContainerTags(entry);
                if (!hasCanonicalTag(tags)) {
                    // Skip untagged platform-specific sub-manifests and OCI referrer entries
                    // (cosign attestation containers are tagged sha256-{digest} with no human tag)
                    continue;
                }
                versions.add(new GithubContainerImageVersionRef(
                        owner,
                        packageName,
                        buildGhcrImageRepository(owner, packageName),
                        digest,
                        tags));
            }
            if (root.size() < 100) {
                break;
            }
            ensureCanContinuePaging(response, "GitHub package versions API", page);
        }
        return versions;
    }

    private int maxCollectionPages() {
        return Math.max(1, maxPagesPerCollection);
    }

    private void ensureCanContinuePaging(ResponseEntity<?> response, String operationName, int page) throws IOException {
        HttpHeaders headers = response.getHeaders();
        String remainingHeader = headers.getFirst("X-RateLimit-Remaining");
        if (remainingHeader != null && !remainingHeader.isBlank()) {
            try {
                int remaining = Integer.parseInt(remainingHeader.trim());
                if (remaining <= Math.max(0, minRateLimitRemaining)) {
                    throw new IOException(operationName + " paused because the GitHub API rate limit is nearly exhausted (remaining: "
                            + remaining + ")");
                }
            } catch (NumberFormatException ignored) {
                // Ignore malformed rate limit headers and continue with normal paging behavior.
            }
        }
        if (page >= maxCollectionPages()) {
            throw new IOException(operationName + " exceeded the configured page limit of " + maxCollectionPages()
                    + ". Narrow the scope or increase app.github.max-pages-per-collection.");
        }
    }

    private JsonNode parseArrayResponse(String payload, String responseLabel) throws IOException {
        JsonNode root;
        try {
            root = objectMapper.readTree(payload == null ? "[]" : payload);
        } catch (Exception e) {
            throw new IOException("Failed to parse " + responseLabel + " response", e);
        }
        if (!root.isArray()) {
            throw new IOException("Unexpected " + responseLabel + " response format");
        }
        return root;
    }

    private GithubAttestedSbomResponse fetchAttestedSbomFromEndpoint(
            String normalizedDigest,
            String expectedImageRepository,
            String endpoint,
            String operationName
    ) throws IOException {
        ResponseEntity<String> response = exchangeWithRetry(endpoint, String.class, operationName);
        String payload = response.getBody();
        if (payload == null || payload.isBlank()) {
            throw new IOException("GitHub attestation response was empty");
        }

        ExtractedAttestationSbom extracted = extractAttestedSbom(
                payload,
                normalizedDigest,
                expectedImageRepository == null ? "" : expectedImageRepository.trim().toLowerCase(Locale.ROOT)
        );

        return new GithubAttestedSbomResponse(
                extracted.sbomPayload(),
                response.getStatusCode().value(),
                MediaType.APPLICATION_JSON_VALUE,
                extracted.sbomPayload().length,
                endpoint,
                extracted.predicateType(),
                extracted.subjectName(),
                extracted.attestationCount()
        );
    }

    private Map<String, GithubAttestedSbomResponse> fetchAttestedSbomsFromBulkEndpoint(
            String endpoint,
            List<GithubAttestationLookup> lookups,
            Map<String, Set<String>> expectedRepositoriesByDigest,
            String operationName
    ) throws IOException {
        List<String> subjectDigests = expectedRepositoriesByDigest.keySet().stream().toList();
        if (subjectDigests.isEmpty()) {
            return Map.of();
        }

        HttpHeaders headers = buildHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        Map<String, Object> requestBody = new LinkedHashMap<>();
        requestBody.put("subject_digests", subjectDigests);
        requestBody.put("predicate_type", "sbom");

        ResponseEntity<String> response = exchangeWithRetry(
                endpoint,
                HttpMethod.POST,
                new HttpEntity<>(requestBody, headers),
                String.class,
                operationName);

        String payload = response.getBody();
        if (payload == null || payload.isBlank()) {
            return Map.of();
        }

        Map<String, ExtractedAttestationSbom> extractedByAssetIdentifier = extractAttestedSboms(
                payload,
                expectedRepositoriesByDigest
        );
        if (extractedByAssetIdentifier.isEmpty()) {
            return Map.of();
        }

        Map<String, GithubAttestedSbomResponse> responses = new LinkedHashMap<>();
        for (GithubAttestationLookup lookup : lookups) {
            String assetIdentifier = attestationLookupKey(lookup.imageRepository(), lookup.subjectDigest());
            ExtractedAttestationSbom extracted = extractedByAssetIdentifier.get(assetIdentifier);
            if (extracted == null) {
                continue;
            }
            responses.put(assetIdentifier, new GithubAttestedSbomResponse(
                    extracted.sbomPayload(),
                    response.getStatusCode().value(),
                    MediaType.APPLICATION_JSON_VALUE,
                    extracted.sbomPayload().length,
                    endpoint,
                    extracted.predicateType(),
                    extracted.subjectName(),
                    extracted.attestationCount()
            ));
        }
        return responses;
    }

    private ExtractedAttestationSbom extractAttestedSbom(
            String responseBody,
            String normalizedDigest,
            String expectedImageRepository
    ) throws IOException {
        JsonNode root;
        try {
            root = objectMapper.readTree(responseBody);
        } catch (Exception e) {
            throw new IOException("Failed to parse GitHub attestation response", e);
        }

        List<JsonNode> attestationNodes = collectAttestationNodes(root);
        if (attestationNodes.isEmpty()) {
            throw new IOException("No GitHub attestations were returned for subject digest " + normalizedDigest);
        }

        String expectedDigestHex = normalizedDigest.substring("sha256:".length());
        for (JsonNode attestationNode : attestationNodes) {
            JsonNode envelope = resolveEnvelope(attestationNode);
            String dssePayload = textValue(envelope, "payload");
            if (dssePayload == null) {
                continue;
            }

            JsonNode statement = parseStatementPayload(dssePayload);
            if (statement == null) {
                continue;
            }

            String predicateType = textValue(statement, "predicateType");
            JsonNode predicate = statement.path("predicate");
            if (!isSupportedSbomPredicate(predicateType, predicate)) {
                continue;
            }

            SubjectMatch match = matchSubject(statement.path("subject"), expectedDigestHex, expectedImageRepository);
            if (!match.digestMatched()) {
                continue;
            }

            byte[] sbomPayload;
            try {
                sbomPayload = objectMapper.writeValueAsBytes(predicate);
            } catch (Exception e) {
                throw new IOException("Failed to serialize attested SBOM payload", e);
            }
            return new ExtractedAttestationSbom(
                    sbomPayload,
                    predicateType == null ? "unknown" : predicateType,
                    match.subjectName(),
                    attestationNodes.size()
            );
        }

        throw new IOException("No supported SBOM attestation matched subject digest " + normalizedDigest);
    }

    private Map<String, ExtractedAttestationSbom> extractAttestedSboms(
            String responseBody,
            Map<String, Set<String>> expectedRepositoriesByDigest
    ) throws IOException {
        JsonNode root;
        try {
            root = objectMapper.readTree(responseBody);
        } catch (Exception e) {
            throw new IOException("Failed to parse GitHub attestation response", e);
        }

        List<JsonNode> attestationNodes = collectAttestationNodes(root);
        if (attestationNodes.isEmpty()) {
            return Map.of();
        }

        Map<String, ExtractedAttestationSbom> matches = new LinkedHashMap<>();
        for (JsonNode attestationNode : attestationNodes) {
            JsonNode envelope = resolveEnvelope(attestationNode);
            String dssePayload = textValue(envelope, "payload");
            if (dssePayload == null) {
                continue;
            }

            JsonNode statement = parseStatementPayload(dssePayload);
            if (statement == null) {
                continue;
            }

            String predicateType = textValue(statement, "predicateType");
            JsonNode predicate = statement.path("predicate");
            if (!isSupportedSbomPredicate(predicateType, predicate)) {
                continue;
            }

            byte[] sbomPayload;
            try {
                sbomPayload = objectMapper.writeValueAsBytes(predicate);
            } catch (Exception e) {
                throw new IOException("Failed to serialize attested SBOM payload", e);
            }

            JsonNode subjectNode = statement.path("subject");
            if (!subjectNode.isArray()) {
                continue;
            }
            for (JsonNode subject : subjectNode) {
                String subjectName = textValue(subject, "name");
                String normalizedSubjectRepository = normalizeContainerRepository(subjectName);
                String subjectDigest = normalizeDigest(textValue(subject.path("digest"), "sha256"));
                if (subjectDigest.isBlank()) {
                    continue;
                }
                Set<String> expectedRepositories = expectedRepositoriesByDigest.get(subjectDigest);
                if (expectedRepositories == null || expectedRepositories.isEmpty()) {
                    continue;
                }
                for (String expectedRepository : expectedRepositories) {
                    if (!subjectMatchesExpectedImageRepository(normalizedSubjectRepository, expectedRepository)) {
                        continue;
                    }
                    String assetIdentifier = attestationLookupKey(expectedRepository, subjectDigest);
                    matches.putIfAbsent(assetIdentifier, new ExtractedAttestationSbom(
                            sbomPayload,
                            predicateType == null ? "unknown" : predicateType,
                            subjectName,
                            attestationNodes.size()
                    ));
                }
            }
        }
        return matches;
    }

    private List<JsonNode> collectAttestationNodes(JsonNode root) {
        if (root == null || root.isMissingNode() || root.isNull()) {
            return List.of();
        }
        if (root.path("attestations").isArray()) {
            List<JsonNode> nodes = new ArrayList<>();
            root.path("attestations").forEach(nodes::add);
            return nodes;
        }
        if (root.isArray()) {
            List<JsonNode> nodes = new ArrayList<>();
            root.forEach(nodes::add);
            return nodes;
        }
        if (root.has("bundle") || root.has("dsseEnvelope") || root.has("dsse_envelope")) {
            return List.of(root);
        }
        return List.of();
    }

    private JsonNode resolveEnvelope(JsonNode attestationNode) {
        JsonNode bundle = attestationNode.path("bundle");
        if (bundle.isMissingNode() || bundle.isNull()) {
            bundle = attestationNode.path("verification_bundle");
        }
        if (bundle.isMissingNode() || bundle.isNull()) {
            bundle = attestationNode;
        }

        JsonNode envelope = bundle.path("dsseEnvelope");
        if (!envelope.isMissingNode() && !envelope.isNull()) {
            return envelope;
        }
        return bundle.path("dsse_envelope");
    }

    private JsonNode parseStatementPayload(String dssePayload) {
        try {
            byte[] decoded = Base64.getDecoder().decode(dssePayload);
            return objectMapper.readTree(new String(decoded, StandardCharsets.UTF_8));
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isSupportedSbomPredicate(String predicateType, JsonNode predicate) {
        if (predicate == null || predicate.isMissingNode() || predicate.isNull() || !predicate.isObject()) {
            return false;
        }
        String normalizedPredicateType = predicateType == null ? "" : predicateType.trim().toLowerCase(Locale.ROOT);
        if (normalizedPredicateType.contains("spdx") || normalizedPredicateType.contains("cyclonedx")) {
            return true;
        }
        return predicate.has("spdxVersion") || predicate.has("bomFormat");
    }

    private SubjectMatch matchSubject(JsonNode subjectNode, String expectedDigestHex, String expectedImageRepository) {
        if (!subjectNode.isArray()) {
            return SubjectMatch.notMatched();
        }

        for (JsonNode subject : subjectNode) {
            String subjectName = textValue(subject, "name");
            JsonNode digestNode = subject.path("digest");
            String digestHex = textValue(digestNode, "sha256");
            boolean digestMatched = digestHex != null && digestHex.equalsIgnoreCase(expectedDigestHex);
            if (!digestMatched) {
                continue;
            }

            if (expectedImageRepository == null || expectedImageRepository.isBlank()) {
                return new SubjectMatch(true, subjectName);
            }
            String normalizedSubjectName = normalizeContainerRepository(subjectName);
            if (subjectMatchesExpectedImageRepository(normalizedSubjectName, expectedImageRepository)) {
                return new SubjectMatch(true, subjectName);
            }
        }

        return SubjectMatch.notMatched();
    }

    private boolean subjectMatchesExpectedImageRepository(String normalizedSubjectName, String expectedImageRepository) {
        if (normalizedSubjectName == null || normalizedSubjectName.isBlank()
                || expectedImageRepository == null || expectedImageRepository.isBlank()) {
            return false;
        }
        String normalizedExpectedRepository = normalizeContainerRepository(expectedImageRepository);
        if (normalizedSubjectName.equals(normalizedExpectedRepository)
                || normalizedSubjectName.endsWith("/" + normalizedExpectedRepository)
                || normalizedSubjectName.contains(normalizedExpectedRepository + "@")) {
            return true;
        }

        String subjectWithoutRegistry = stripRegistryPrefix(normalizedSubjectName);
        String expectedWithoutRegistry = stripRegistryPrefix(normalizedExpectedRepository);
        return !subjectWithoutRegistry.isBlank() && subjectWithoutRegistry.equals(expectedWithoutRegistry);
    }

    private String normalizeContainerRepository(String value) {
        String normalized = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        if (normalized.isBlank()) {
            return "";
        }
        if (normalized.startsWith("docker://")) {
            normalized = normalized.substring("docker://".length());
        } else if (normalized.startsWith("oci://")) {
            normalized = normalized.substring("oci://".length());
        } else if (normalized.startsWith("https://")) {
            normalized = normalized.substring("https://".length());
        } else if (normalized.startsWith("http://")) {
            normalized = normalized.substring("http://".length());
        }
        if (normalized.startsWith("//")) {
            normalized = normalized.substring(2);
        }
        if (normalized.startsWith("pkg:docker/")) {
            normalized = normalized.substring("pkg:docker/".length());
        }

        int queryIndex = normalized.indexOf('?');
        if (queryIndex >= 0) {
            normalized = normalized.substring(0, queryIndex);
        }
        int fragmentIndex = normalized.indexOf('#');
        if (fragmentIndex >= 0) {
            normalized = normalized.substring(0, fragmentIndex);
        }
        int digestIndex = normalized.indexOf('@');
        if (digestIndex >= 0) {
            normalized = normalized.substring(0, digestIndex);
        }

        int lastSlash = normalized.lastIndexOf('/');
        int lastColon = normalized.lastIndexOf(':');
        if (lastColon > lastSlash) {
            normalized = normalized.substring(0, lastColon);
        }

        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private String stripRegistryPrefix(String normalizedRepository) {
        if (normalizedRepository == null || normalizedRepository.isBlank()) {
            return "";
        }
        int firstSlash = normalizedRepository.indexOf('/');
        if (firstSlash <= 0) {
            return normalizedRepository;
        }
        String firstSegment = normalizedRepository.substring(0, firstSlash);
        if (firstSegment.contains(".") || firstSegment.contains(":") || "localhost".equals(firstSegment)) {
            return normalizedRepository.substring(firstSlash + 1);
        }
        return normalizedRepository;
    }

    private String attestationLookupKey(String imageRepository, String subjectDigest) {
        return normalizeContainerRepository(imageRepository) + "@" + normalizeDigest(subjectDigest);
    }

    private String textValue(JsonNode node, String fieldName) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return null;
        }
        JsonNode valueNode = node.path(fieldName);
        if (valueNode.isMissingNode() || valueNode.isNull()) {
            return null;
        }
        String value = valueNode.asText("");
        return value.isBlank() ? null : value.trim();
    }

    private String extractContainerDigest(JsonNode versionNode) {
        if (versionNode == null || versionNode.isMissingNode() || versionNode.isNull()) {
            return "";
        }
        String digest = normalizeDigest(textValue(versionNode, "name"));
        if (!digest.isBlank()) {
            return digest;
        }
        digest = normalizeDigest(textValue(versionNode.path("metadata").path("container"), "digest"));
        return digest.isBlank() ? "" : digest;
    }

    private List<String> extractContainerTags(JsonNode versionNode) {
        JsonNode tagsNode = versionNode.path("metadata").path("container").path("tags");
        if (!tagsNode.isArray()) {
            return List.of();
        }
        Set<String> tags = new LinkedHashSet<>();
        tagsNode.forEach(tagNode -> {
            String tag = normalize(tagNode.asText(""));
            if (!tag.isBlank()) {
                tags.add(tag);
            }
        });
        if (tags.isEmpty()) {
            return List.of();
        }
        List<String> values = new ArrayList<>(tags);
        Collections.sort(values);
        return values;
    }

    private boolean hasCanonicalTag(List<String> tags) {
        if (tags == null || tags.isEmpty()) {
            return false;
        }
        // OCI referrer entries (cosign/attest) use tags of the form sha256-{64-hex-chars}
        // These are internal attestation storage artifacts, not canonical image tags
        return tags.stream().anyMatch(tag -> !tag.startsWith("sha256-") || tag.length() != 71);
    }

    private String normalizeDigest(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        if (!normalized.startsWith("sha256:")) {
            normalized = "sha256:" + normalized;
        }
        String hex = normalized.substring("sha256:".length());
        if (hex.length() != 64) {
            return "";
        }
        for (int i = 0; i < hex.length(); i++) {
            char ch = hex.charAt(i);
            boolean digit = ch >= '0' && ch <= '9';
            boolean lowerHex = ch >= 'a' && ch <= 'f';
            if (!digit && !lowerHex) {
                return "";
            }
        }
        return normalized;
    }

    private record ExtractedAttestationSbom(
            byte[] sbomPayload,
            String predicateType,
            String subjectName,
            int attestationCount
    ) {
    }

    private record SubjectMatch(
            boolean digestMatched,
            String subjectName
    ) {
        private static SubjectMatch notMatched() {
            return new SubjectMatch(false, null);
        }
    }

    private <T> ResponseEntity<T> exchangeWithRetry(
            String endpoint,
            Class<T> responseType,
            String operationName
    ) throws IOException {
        return exchangeWithRetry(
                endpoint,
                HttpMethod.GET,
                new HttpEntity<>(buildHeaders()),
                responseType,
                operationName
        );
    }

    private <T> ResponseEntity<T> exchangeWithRetry(
            String endpoint,
            HttpMethod method,
            HttpEntity<?> requestEntity,
            Class<T> responseType,
            String operationName
    ) throws IOException {
        return outboundHttpClient.exchange(
                endpoint,
                method,
                requestEntity,
                responseType,
                operationName,
                outboundPolicy(),
                context -> classifyFailure(context, operationName)
        );
    }

    private OutboundPolicy outboundPolicy() {
        return outboundPolicyFactory
                .forProvider("github", 0L, maxRetries, retryBaseBackoffMs)
                .withMaxBackoffMs(15000L)
                .withRetryableStatuses(Set.of(429, 500, 502, 503, 504));
    }

    private OutboundFailureDecision<IOException> classifyFailure(
            OutboundFailureContext context,
            String operationName
    ) {
        Integer statusCode = context.statusCodeValue();
        if (statusCode != null) {
            if (statusCode == 404) {
                return OutboundFailureDecision.fail(
                        new GithubNotFoundException(operationName + " request returned 404", context.error())
                );
            }
            if (statusCode == 401 || statusCode == 403) {
                return OutboundFailureDecision.fail(
                        new IOException(formatAuthorizationError(operationName, statusCode), context.error())
                );
            }
            return new OutboundFailureDecision<>(
                    context.policy().isRetryableStatus(statusCode),
                    context.retryAfterDelayMs(),
                    new IOException(operationName + " request failed with status " + statusCode, context.error())
            );
        }
        return new OutboundFailureDecision<>(
                true,
                null,
                new IOException("Failed to call " + operationName + " after retries", context.error())
        );
    }

    private String formatAuthorizationError(String operationName, int statusCode) {
        String tokenHint = hasToken()
                ? "The configured GITHUB_API_TOKEN may be invalid or missing required scopes."
                : githubTokenProvider.configurationHint();
        if ("GitHub packages API".equals(operationName) || "GitHub package versions API".equals(operationName)) {
            return operationName + " request failed with status " + statusCode
                    + ". GHCR discovery requires a GitHub token with at least read:packages access. "
                    + tokenHint;
        }
        if (operationName != null && operationName.toLowerCase(Locale.ROOT).contains("attestation")) {
            return operationName + " request failed with status " + statusCode
                    + ". GitHub attestation lookup requires a token that can read the target package/repository. "
                    + tokenHint;
        }
        return operationName + " request failed with status " + statusCode + ". " + tokenHint;
    }

    private HttpHeaders buildHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.parseMediaType("application/vnd.github+json")));
        headers.set("X-GitHub-Api-Version", "2022-11-28");
        headers.set("User-Agent", "vulnwatch-backend/1.0");
        githubTokenProvider.applyBearerAuth(headers);
        return headers;
    }

    private static final class GithubNotFoundException extends IOException {
        private GithubNotFoundException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
