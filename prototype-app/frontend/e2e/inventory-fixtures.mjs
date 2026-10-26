// Deterministic Inventory and lifecycle fixtures for UI 2.0 visual/behaviour review (P4).
//
// Shapes follow frontend/src/features/inventory/api-types.ts, features/software-identities/types.ts,
// features/eol/types.ts, features/ai-security/types.ts and the BOM / AI-BOM types in api/client.ts.
// All names, identifiers, ARNs, digests and counts are synthetic. List endpoints narrow and page
// only as far as needed to make filters and pagination observable; writes return canned results
// and nothing is persisted. Not authenticated evidence.
import { findings as findingRecords } from './findings-fixtures.mjs';
import { FIXED_TIME } from './time.mjs';

const BASE = FIXED_TIME;
const day = 86_400_000;
const iso = (offsetDays) => new Date(BASE + offsetDays * day).toISOString();
const isoDate = (offsetDays) => iso(offsetDays).slice(0, 10);
const AWS_ACCOUNT = '111122223333';
const AZURE_SUB = 'sub-7f3a2c91-0d4e-4b8a-9c61-fixture00001';

export const PRIMARY_HOST_ID = 'host-prod-api-gw-01';
export const PRIMARY_SOFTWARE_IDENTITY_ID = 'si-log4j-core';
export const PRIMARY_AI_ASSET_ID = 'ai-agent-claims-triage';
export const PRIMARY_DECLARED_RESOURCE_ID = 'dr-claims-model';
export const PRIMARY_BOM_ID = 'bom-0001';

// ── Assets ──────────────────────────────────────────────────────────────────
// [id, type, name, environment, ownerTeam, criticality, state]
const ASSET_ROWS = [
  [PRIMARY_HOST_ID, 'HOST', 'prod-api-gw-01', 'production-edge', 'Core Infrastructure', 'CRITICAL', 'ACTIVE'],
  ['host-billing-core', 'HOST', 'billing-core', 'production', 'Payments Platform', 'HIGH', 'ACTIVE'],
  ['host-vpn-edge-02', 'HOST', 'vpn-edge-02', 'dmz', 'Core Infrastructure', 'HIGH', 'ACTIVE'],
  ['host-aks-node-pool-3', 'HOST', 'aks-node-pool-3', 'production', 'Platform Engineering', 'MEDIUM', 'ACTIVE'],
  ['host-etl-worker-07', 'HOST', 'etl-worker-07', 'staging', 'Data Platform', 'MEDIUM', 'ACTIVE'],
  ['host-legacy-reporting-01', 'HOST', 'legacy-reporting-01', 'production', 'Finance Systems', 'HIGH', 'RETIRED'],
  ['host-build-agent-win-04', 'HOST', 'build-agent-win-04', 'ci', 'Developer Productivity', 'LOW', 'ACTIVE'],
  ['host-bastion-eu-west-1a', 'HOST', 'bastion-eu-west-1a', 'production', 'Core Infrastructure', 'HIGH', 'ACTIVE'],
  ['host-ml-gpu-node-12', 'HOST', 'ml-gpu-node-12', 'research', 'AI Platform', 'MEDIUM', 'INACTIVE'],
  ['host-kafka-broker-03', 'HOST', 'kafka-broker-03', 'production', 'Data Platform', 'HIGH', 'ACTIVE'],
  ['host-dc-ad-02', 'HOST', 'dc-ad-02', 'corporate', 'Identity', 'CRITICAL', 'ACTIVE'],
  ['host-cmdb-orphan-7781', 'HOST', 'cmdb-orphan-7781', undefined, undefined, 'UNKNOWN', 'UNKNOWN'],
  ['img-payments-svc', 'CONTAINER_IMAGE', 'payments-svc', 'production', 'Payments Platform', 'CRITICAL', 'ACTIVE'],
  ['img-auth-svc', 'CONTAINER_IMAGE', 'auth-svc', 'production', 'Identity', 'HIGH', 'ACTIVE'],
  ['img-checkout-web', 'CONTAINER_IMAGE', 'checkout-web', 'production', 'Payments Platform', 'HIGH', 'ACTIVE'],
  ['img-search-indexer', 'CONTAINER_IMAGE', 'search-indexer', 'staging', 'Data Platform', 'MEDIUM', 'ACTIVE'],
  ['img-notification-worker', 'CONTAINER_IMAGE', 'notification-worker', 'production', undefined, 'LOW', 'ACTIVE'],
  ['img-claims-inference-gateway', 'CONTAINER_IMAGE', 'claims-inference-gateway-with-a-deliberately-long-repository-name', 'production', 'AI Platform', 'HIGH', 'ACTIVE'],
  ['app-analytics-pipeline', 'APPLICATION', 'analytics-pipeline', 'production', 'Data Platform', 'MEDIUM', 'ACTIVE'],
  ['app-customer-portal', 'APPLICATION', 'customer-portal', 'production', 'Digital Channels', 'CRITICAL', 'ACTIVE'],
  ['app-mobile-bff', 'APPLICATION', 'mobile-bff', 'production', 'Digital Channels', 'HIGH', 'ACTIVE'],
  ['app-internal-wiki', 'APPLICATION', 'internal-wiki', 'corporate', undefined, 'LOW', 'ACTIVE'],
  ['app-claims-engine', 'APPLICATION', 'claims-engine', 'production', 'Claims Engineering', 'HIGH', 'ACTIVE'],
];

const identifierFor = (type, name) => {
  if (type === 'CONTAINER_IMAGE') return `${AWS_ACCOUNT}.dkr.ecr.us-east-1.amazonaws.com/fixture/${name}@sha256:${'9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'.slice(0, 64)}`;
  if (type === 'APPLICATION') return `github.com/fixture-org/${name}`;
  return `${name}.fixture.internal`;
};

export const assets = ASSET_ROWS.map(([id, type, name, environment, ownerTeam, businessCriticality, state], index) => ({
  id, type, name, identifier: identifierFor(type, name), serviceName: type === 'HOST' ? undefined : name,
  environment, ownerTeam, ownerEmail: ownerTeam ? `${ownerTeam.toLowerCase().replace(/\s+/g, '.')}@example.test` : undefined,
  businessCriticality, state,
  lastInventoryAt: index === 11 ? undefined : iso(-(index % 9) * 0.7 - (index === 5 ? 48 : 0)),
  lastCmdbSyncAt: index % 4 === 3 ? undefined : iso(-1 - (index % 3)),
}));
const assetById = new Map(assets.map((asset) => [asset.id, asset]));
const A = Object.fromEntries(assets.map((asset, index) => [asset.name.split('-with-')[0], index]));

// ── Software identities ─────────────────────────────────────────────────────
// lifecycle: eol | near | supported | unknown. deployments: asset short names.
const LIFECYCLE = {
  eol: (offset) => ({ isEol: true, eolDaysRemaining: offset, eolDate: isoDate(offset) }),
  near: (offset) => ({ isEol: false, eolDaysRemaining: offset, eolDate: isoDate(offset) }),
  supported: (offset) => ({ isEol: false, eolDaysRemaining: offset, eolDate: isoDate(offset) }),
  unknown: () => ({}),
};

const IDENTITIES = [
  {
    key: 'log4j-core', displayName: 'log4j-core', vendor: 'Apache Software Foundation', product: 'log4j-core', ecosystem: 'maven',
    purl: 'pkg:maven/org.apache.logging.log4j/log4j-core', cpe: 'cpe:2.3:a:apache:log4j', eolSlug: 'log4j', mappingConfirmed: true,
    versions: [
      ['2.14.1', 'supported', 820, ['prod-api-gw-01', 'checkout-web'], ['CVE-2026-31337', 'CVE-2026-28810', 'CVE-2026-27455', 'CVE-2026-24301']],
      ['2.13.3', 'supported', 820, ['payments-svc'], ['CVE-2026-31337', 'CVE-2026-27455', 'CVE-2026-21987']],
      ['2.12.1', 'eol', -540, ['legacy-reporting-01'], ['CVE-2026-31337', 'CVE-2026-19044', 'CVE-2026-24301']],
      ['2.17.2', 'supported', 820, ['analytics-pipeline', 'claims-engine'], []],
    ],
  },
  { key: 'openssl', displayName: 'OpenSSL', vendor: 'OpenSSL Project', product: 'openssl', ecosystem: 'deb', purl: 'pkg:deb/ubuntu/openssl', cpe: 'cpe:2.3:a:openssl:openssl', eolSlug: 'openssl',
    versions: [
      ['3.0.7', 'near', 38, ['prod-api-gw-01', 'vpn-edge-02', 'aks-node-pool-3'], ['CVE-2026-28810', 'CVE-2026-11402']],
      ['1.1.1w', 'eol', -1050, ['billing-core', 'legacy-reporting-01'], ['CVE-2026-11402', 'CVE-2026-10988', 'CVE-2026-10431']],
      ['3.2.1', 'supported', 640, ['bastion-eu-west-1a', 'ml-gpu-node-12', 'kafka-broker-03', 'auth-svc'], []],
    ] },
  { key: 'nginx', displayName: 'nginx', vendor: 'F5, Inc.', product: 'nginx', ecosystem: 'deb', purl: 'pkg:deb/debian/nginx', cpe: 'cpe:2.3:a:f5:nginx', eolSlug: 'nginx',
    versions: [
      ['1.22.0', 'eol', -380, ['prod-api-gw-01', 'vpn-edge-02'], ['CVE-2026-21987']],
      ['1.24.0', 'supported', 210, ['checkout-web', 'customer-portal'], []],
    ] },
  { key: 'postgresql', displayName: 'PostgreSQL', vendor: 'PostgreSQL Global Development Group', product: 'postgresql', ecosystem: 'rpm', purl: 'pkg:rpm/redhat/postgresql-server', cpe: 'cpe:2.3:a:postgresql:postgresql', eolSlug: 'postgresql', mappingConfirmed: true,
    versions: [
      ['11.22', 'eol', -720, ['billing-core'], ['CVE-2026-15520', 'CVE-2026-15521']],
      ['14.6', 'near', 74, ['etl-worker-07'], ['CVE-2026-15520']],
      ['16.2', 'supported', 1100, ['kafka-broker-03'], []],
    ] },
  { key: 'python', displayName: 'Python', vendor: 'Python Software Foundation', product: 'python', ecosystem: 'generic', purl: 'pkg:generic/python', cpe: 'cpe:2.3:a:python:python', eolSlug: 'python',
    versions: [
      ['3.8.18', 'eol', -390, ['etl-worker-07', 'legacy-reporting-01'], ['CVE-2026-13007']],
      ['3.11.7', 'supported', 730, ['ml-gpu-node-12', 'search-indexer'], []],
      ['3.12.1', 'supported', 1090, ['bastion-eu-west-1a'], []],
    ] },
  { key: 'nodejs', displayName: 'Node.js', vendor: 'OpenJS Foundation', product: 'node', ecosystem: 'npm', purl: 'pkg:generic/nodejs', cpe: 'cpe:2.3:a:nodejs:node.js', eolSlug: 'nodejs',
    versions: [
      ['18.19.0', 'eol', -177, ['notification-worker', 'mobile-bff'], ['CVE-2026-17110', 'CVE-2026-17111']],
      ['20.11.0', 'near', 18, ['checkout-web', 'customer-portal', 'build-agent-win-04'], ['CVE-2026-17111']],
      ['22.4.1', 'supported', 550, ['auth-svc'], []],
    ] },
  { key: 'openjdk', displayName: 'OpenJDK Runtime Environment', vendor: 'Eclipse Adoptium', product: 'openjdk', ecosystem: 'generic', purl: 'pkg:generic/openjdk', cpe: 'cpe:2.3:a:eclipse:temurin', eolSlug: 'eclipse-temurin',
    versions: [
      ['8u392', 'supported', 1500, ['legacy-reporting-01'], []],
      ['11.0.21', 'near', 61, ['billing-core', 'kafka-broker-03'], ['CVE-2026-12230']],
      ['17.0.9', 'supported', 1095, ['prod-api-gw-01', 'payments-svc'], []],
    ] },
  { key: 'dotnet-framework', displayName: 'Microsoft .NET Framework', vendor: 'Microsoft Corporation', product: '.net framework', ecosystem: 'windows', cpe: 'cpe:2.3:a:microsoft:.net_framework', eolSlug: 'dotnetfx',
    versions: [
      ['4.5.2', 'eol', -1290, ['legacy-reporting-01'], ['CVE-2026-14002']],
      ['4.8.1', 'supported', 2400, ['build-agent-win-04', 'dc-ad-02'], []],
    ] },
  { key: 'windows-server', displayName: 'Windows Server', vendor: 'Microsoft Corporation', product: 'windows server', ecosystem: 'windows', cpe: 'cpe:2.3:o:microsoft:windows_server', eolSlug: 'windows-server', mappingConfirmed: true, os: true,
    hostName: (version) => `Microsoft Windows Server ${version} Datacenter`,
    versions: [
      ['2012 R2', 'eol', -1110, ['legacy-reporting-01'], ['CVE-2026-14410', 'CVE-2026-14411']],
      ['2019', 'supported', 806, ['build-agent-win-04'], []],
      ['2022', 'supported', 1810, ['dc-ad-02'], []],
    ] },
  { key: 'ubuntu', displayName: 'Ubuntu', vendor: 'Canonical Ltd.', product: 'ubuntu', ecosystem: 'os', cpe: 'cpe:2.3:o:canonical:ubuntu_linux', eolSlug: 'ubuntu', os: true,
    hostName: (version) => `Ubuntu ${version} LTS`,
    versions: [
      ['22.04', 'supported', 185, ['prod-api-gw-01', 'ml-gpu-node-12'], []],
      ['20.04', 'eol', -510, ['aks-node-pool-3'], ['CVE-2026-16001']],
    ] },
  { key: 'rhel', displayName: 'Red Hat Enterprise Linux', vendor: 'Red Hat, Inc.', product: 'enterprise linux', ecosystem: 'os', cpe: 'cpe:2.3:o:redhat:enterprise_linux', eolSlug: 'rhel', os: true,
    hostName: (version) => `Red Hat Enterprise Linux Server ${version}`,
    versions: [['7.9', 'eol', -846, ['billing-core'], ['CVE-2026-16420']]] },
  { key: 'debian', displayName: 'Debian GNU/Linux', vendor: 'Debian Project', product: 'debian', ecosystem: 'os', cpe: 'cpe:2.3:o:debian:debian_linux', eolSlug: 'debian', os: true,
    hostName: (version) => `Debian ${version} (bullseye)`,
    versions: [['11', 'eol', -55, ['vpn-edge-02'], []]] },
  { key: 'amazon-linux', displayName: 'Amazon Linux', vendor: 'Amazon Web Services', product: 'amazon linux', ecosystem: 'os', cpe: 'cpe:2.3:o:amazon:linux', eolSlug: 'amazon-linux', os: true,
    hostName: (version) => `Amazon Linux ${version}`,
    versions: [['2', 'near', 22, ['etl-worker-07'], []], ['2023', 'supported', 1600, ['bastion-eu-west-1a'], []]] },
  { key: 'rocky-linux', displayName: 'Rocky Linux', vendor: 'Rocky Enterprise Software Foundation', product: 'rocky linux', ecosystem: 'os', cpe: 'cpe:2.3:o:rocky:rocky_linux', eolSlug: 'rocky-linux', os: true,
    hostName: (version) => `Rocky Linux ${version} (Green Obsidian)`,
    versions: [['8.9', 'supported', 940, ['kafka-broker-03'], []]] },
  { key: 'curl', displayName: 'curl', vendor: 'curl project', product: 'curl', ecosystem: 'deb', purl: 'pkg:deb/ubuntu/curl', cpe: 'cpe:2.3:a:haxx:curl',
    versions: [
      ['8.1.0', 'unknown', 0, ['prod-api-gw-01', 'aks-node-pool-3', 'etl-worker-07'], ['CVE-2026-19044']],
      ['7.29.0', 'unknown', 0, ['billing-core'], ['CVE-2026-19044', 'CVE-2026-18110']],
    ] },
  { key: 'lodash', displayName: 'lodash', vendor: undefined, product: 'lodash', ecosystem: 'npm', purl: 'pkg:npm/lodash', needsEolMapping: true,
    versions: [['4.17.20', 'unknown', 0, ['checkout-web', 'customer-portal', 'mobile-bff', 'internal-wiki'], ['CVE-2026-20201']]] },
  { key: 'jackson-databind', displayName: 'jackson-databind', vendor: 'FasterXML', product: 'jackson-databind', ecosystem: 'maven', purl: 'pkg:maven/com.fasterxml.jackson.core/jackson-databind', needsEolMapping: true,
    versions: [['2.13.2', 'unknown', 0, ['payments-svc', 'claims-engine'], ['CVE-2026-24301']]] },
  { key: 'spring-webmvc', displayName: 'spring-webmvc', vendor: 'VMware Tanzu', product: 'spring-webmvc', ecosystem: 'maven', purl: 'pkg:maven/org.springframework/spring-webmvc', cpe: 'cpe:2.3:a:vmware:spring_framework', eolSlug: 'spring-framework',
    versions: [['5.3.18', 'eol', -425, ['payments-svc', 'claims-engine'], ['CVE-2026-27455']], ['6.1.4', 'supported', 300, ['auth-svc'], []]] },
  { key: 'glibc', displayName: 'GNU C Library', vendor: 'GNU Project', product: 'glibc', ecosystem: 'deb', purl: 'pkg:deb/ubuntu/libc6',
    versions: [['2.35', 'unknown', 0, ['prod-api-gw-01', 'ml-gpu-node-12'], []]] },
  { key: 'kafka', displayName: 'Apache Kafka', vendor: 'Apache Software Foundation', product: 'kafka', ecosystem: 'maven', purl: 'pkg:maven/org.apache.kafka/kafka_2.13', cpe: 'cpe:2.3:a:apache:kafka', eolSlug: 'apache-kafka',
    versions: [['3.4.0', 'near', 9, ['kafka-broker-03'], ['CVE-2026-22100']]] },
  { key: 'docker-engine', displayName: 'Docker Engine', vendor: 'Docker, Inc.', product: 'docker-ce', ecosystem: 'deb', cpe: 'cpe:2.3:a:docker:docker',
    versions: [['20.10.24', 'eol', -460, ['aks-node-pool-3', 'build-agent-win-04'], []]], eolSlug: 'docker-engine' },
  { key: 'semver', displayName: 'semver', vendor: undefined, product: 'semver', ecosystem: 'npm', purl: 'pkg:npm/semver', needsEolMapping: true,
    versions: [['7.5.1', 'unknown', 0, ['notification-worker'], []]] },
  ...[['zlib', 'zlib', 'apk', '1.3.1-r0'], ['busybox', 'BusyBox', 'apk', '1.36.1-r15'], ['ca-certificates', 'ca-certificates', 'apk', '20240226-r0'],
    ['musl', 'musl libc', 'apk', '1.2.4_git20230717-r4'], ['libssl3', 'libssl3', 'apk', '3.1.4-r5']].map(([key, displayName, ecosystem, version], index) => ({
    key, displayName, vendor: index === 3 ? undefined : 'Alpine Linux', product: key, ecosystem, purl: `pkg:apk/alpine/${key}?arch=x86_64&distro=alpine-3.19`,
    versions: [[version, index === 4 ? 'near' : 'unknown', 33, ['payments-svc', 'auth-svc', 'checkout-web', 'search-indexer', 'notification-worker', 'claims-inference-gateway'], index === 4 ? ['CVE-2026-11402'] : []]],
  })),
  { key: 'bedrock-runtime-sdk', displayName: 'aws-java-sdk-bedrockruntime', vendor: 'Amazon Web Services', product: 'aws-java-sdk-bedrockruntime', ecosystem: 'maven',
    purl: 'pkg:maven/com.amazonaws/aws-java-sdk-bedrockruntime?type=jar&classifier=fixture-shaded-with-a-long-qualifier-for-wrapping', eolSlug: undefined,
    versions: [['1.12.661', 'unknown', 0, ['claims-inference-gateway', 'claims-engine'], []]] },
  { key: 'fixture-endpoint-agent', displayName: 'Fixture Endpoint Agent', vendor: undefined, product: 'fixture endpoint agent', ecosystem: 'windows',
    versions: [[undefined, 'unknown', 0, ['dc-ad-02', 'legacy-reporting-01'], []]] },
];

const SEVERITY_BY_CVE = (cveId, index) => ['CRITICAL', 'HIGH', 'HIGH', 'MEDIUM', 'LOW'][(Number(cveId.slice(-2)) + index) % 5];

const components = [];
const identities = IDENTITIES.map((identity, identityIndex) => {
  const id = `si-${identity.key}`;
  const versions = identity.versions.map(([version, lifecycle, offset, deployed, cveIds], versionIndex) => {
    const eol = LIFECYCLE[lifecycle](offset);
    const openFindingCount = cveIds.length ? cveIds.length + deployed.length - 1 : 0;
    deployed.forEach((assetName, deployIndex) => {
      const asset = assets[A[assetName]];
      const source = asset.type === 'HOST' ? (deployIndex % 2 ? 'servicenow' : 'aws_ssm') : asset.type === 'CONTAINER_IMAGE' ? 'ecr_scan' : 'sbom';
      components.push({
        id: `comp-${identity.key}-${versionIndex}-${A[assetName]}`, assetId: asset.id, assetName: asset.name, assetIdentifier: asset.identifier, assetType: asset.type,
        componentStatus: asset.state === 'RETIRED' ? 'RETIRED' : 'ACTIVE', ecosystem: identity.ecosystem, packageName: identity.product,
        packageGroup: identity.purl?.split('/')[1], license: identityIndex % 3 === 0 ? 'Apache-2.0' : identityIndex % 3 === 1 ? undefined : 'MIT', scope: 'required',
        version, normalizedName: identity.product, normalizedVersion: version,
        purl: identity.purl ? `${identity.purl.split('?')[0]}${version ? `@${encodeURIComponent(version)}` : ''}${identity.purl.includes('?') ? `?${identity.purl.split('?')[1]}` : ''}` : '',
        componentDigest: `sha256:${(identityIndex * 7919 + versionIndex * 104729 + deployIndex).toString(16).padStart(8, '0')}${'c0ffee'.repeat(9)}a`.slice(0, 71),
        softwareIdentity: identity.displayName, cveCount: cveIds.length, impactedCveCount: Math.max(0, cveIds.length - 1), cveIds,
        sourceSystem: source, sourceType: asset.type === 'HOST' ? 'AGENT' : 'SBOM', sourceReference: asset.type === 'HOST' ? `${source}://${asset.name}/inventory` : `${asset.identifier}/sbom.cdx.json`,
        uploadedAt: asset.type === 'HOST' ? undefined : iso(-3 - deployIndex), lastObservedAt: asset.lastInventoryAt ?? iso(-30), retiredAt: asset.state === 'RETIRED' ? iso(-12) : undefined,
        needsReview: !version || Boolean(identity.needsEolMapping), reviewItemCount: (!version ? 1 : 0) + (identity.needsEolMapping ? 1 : 0),
        reviewMissingVersion: !version, reviewUnmappedSoftware: Boolean(identity.needsEolMapping), reviewLowConfidenceAlias: identity.key === 'bedrock-runtime-sdk', reviewDiscoveryModel: identity.key === 'fixture-endpoint-agent',
        eolSlug: lifecycle === 'unknown' ? undefined : identity.eolSlug, eolCycle: lifecycle === 'unknown' ? undefined : String(version ?? '').split('.').slice(0, 2).join('.'),
        ...eol, lifecycle, identityId: id, publisher: identity.vendor, hostName: identity.hostName?.(version), cpe23: identity.cpe && version ? `${identity.cpe}:${version.replace(/\s+/g, '_').toLowerCase()}:*:*:*:*:*:*:*` : undefined,
      });
    });
    return {
      version, eolSlug: lifecycle === 'unknown' ? undefined : identity.eolSlug, eolCycle: lifecycle === 'unknown' ? undefined : String(version ?? '').split('.').slice(0, 2).join('.'),
      ...eol, supportEndDate: lifecycle === 'unknown' ? undefined : isoDate(offset - 180),
      assetCount: deployed.length, componentCount: deployed.length, openFindingCount,
      criticalFindingCount: cveIds.length >= 3 ? 1 : 0, highFindingCount: cveIds.length >= 2 ? 1 : 0, openVulnerabilityCount: cveIds.length,
      lastObservedAt: iso(-versionIndex * 0.5), lifecycle,
    };
  });
  const sum = (key) => versions.reduce((total, version) => total + version[key], 0);
  const mine = components.filter((component) => component.identityId === id);
  return {
    id, displayName: identity.displayName, canonicalKey: `${identity.ecosystem}/${identity.product}`, vendor: identity.vendor, product: identity.product,
    normalizedKey: `${(identity.vendor ?? 'unknown').toLowerCase().replace(/[^a-z0-9]+/g, '-')}:${identity.product.replace(/\s+/g, '-')}`,
    purl: identity.purl, cpe23: identity.cpe ? `${identity.cpe}:*:*:*:*:*:*:*:*` : undefined,
    assetTypes: [...new Set(mine.map((component) => component.assetType))], ecosystems: [identity.ecosystem],
    sourceSystems: [...new Set(mine.map((component) => component.sourceSystem))], eolSlug: identity.eolSlug,
    mappingConfirmed: Boolean(identity.mappingConfirmed), needsEolMapping: Boolean(identity.needsEolMapping),
    assetCount: new Set(mine.map((component) => component.assetId)).size, componentCount: mine.length, versionCount: versions.length,
    eolComponentCount: mine.filter((component) => component.lifecycle === 'eol').length,
    nearEolComponentCount: mine.filter((component) => component.lifecycle === 'near').length,
    unknownEolComponentCount: mine.filter((component) => component.lifecycle === 'unknown').length,
    openFindingCount: sum('openFindingCount'), criticalFindingCount: sum('criticalFindingCount'), highFindingCount: sum('highFindingCount'),
    openVulnerabilityCount: new Set(identity.versions.flatMap((version) => version[4])).size,
    lastObservedAt: identity.key === 'fixture-endpoint-agent' ? undefined : iso(-(identityIndex % 6) * 0.4),
    versions, os: Boolean(identity.os),
  };
});
const identityById = new Map(identities.map((identity) => [identity.id, identity]));

const stripInternal = ({ lifecycle, identityId, publisher, hostName, cpe23, ...rest }) => rest;
const summaryOf = ({ versions, os, purl, cpe23, ...rest }) => rest;

function identityLifecycleKey(identity) {
  if (identity.eolComponentCount > 0) return 'eol';
  if (identity.nearEolComponentCount > 0) return 'near-eol';
  if (identity.unknownEolComponentCount > 0) return 'unknown';
  return 'supported';
}

function narrowIdentities(params) {
  const query = (params.get('query') ?? '').toLowerCase();
  const assetTypes = params.getAll('assetType');
  const sourceSystems = params.getAll('sourceSystem').map((value) => value.toLowerCase());
  const ecosystems = params.getAll('ecosystem').map((value) => value.toLowerCase());
  const lifecycle = params.get('lifecycle');
  const mappingState = params.get('mappingState');
  const coverage = params.get('coverage');
  const operatingSystem = (params.get('operatingSystem') ?? '').toLowerCase();
  return identities.filter((identity) => {
    if (query && !`${identity.displayName} ${identity.vendor ?? ''} ${identity.product} ${identity.canonicalKey}`.toLowerCase().includes(query)) return false;
    if (assetTypes.length && !identity.assetTypes.some((value) => assetTypes.includes(value))) return false;
    if (sourceSystems.length && !identity.sourceSystems.some((value) => sourceSystems.includes(value))) return false;
    if (ecosystems.length && !identity.ecosystems.some((value) => ecosystems.includes(value))) return false;
    if (lifecycle && identityLifecycleKey(identity) !== lifecycle) return false;
    if (mappingState === 'needs-review' && !identity.needsEolMapping) return false;
    if (mappingState === 'mapped' && !identity.eolSlug) return false;
    if (mappingState === 'manual' && !identity.mappingConfirmed) return false;
    if (mappingState === 'automatic' && (identity.mappingConfirmed || !identity.eolSlug)) return false;
    if (coverage === 'with-vulnerabilities' && identity.openVulnerabilityCount === 0) return false;
    if (coverage === 'with-findings' && identity.openFindingCount === 0) return false;
    if (operatingSystem) {
      const hostIds = new Set(hostDetails().filter((detail) => detail.os.toLowerCase().includes(operatingSystem)).map((detail) => detail.host.assetId));
      if (!components.some((component) => component.identityId === identity.id && hostIds.has(component.assetId))) return false;
    }
    return true;
  });
}

function identityDetail(identity) {
  const mine = components.filter((component) => component.identityId === identity.id);
  return {
    ...summaryOf(identity), purl: identity.purl, cpe23: identity.cpe23,
    bomEvidence: bomEvidenceFor(mine.filter((component) => component.assetType !== 'HOST')),
    versions: identity.versions.map(({ lifecycle, ...version }) => version),
    assets: mine.map((component) => ({
      assetId: component.assetId, assetName: component.assetName, assetIdentifier: component.assetIdentifier, assetType: component.assetType,
      componentId: component.id, packageName: component.packageName, ecosystem: component.ecosystem, version: component.version,
      sourceSystem: component.sourceSystem, eolSlug: component.eolSlug, eolCycle: component.eolCycle, eolDate: component.eolDate,
      isEol: component.isEol, eolDaysRemaining: component.eolDaysRemaining,
      openFindingCount: component.cveCount ? component.cveCount - 1 : 0, openVulnerabilityCount: component.cveCount, lastObservedAt: component.lastObservedAt,
    })),
  };
}

function bomEvidenceFor(bomComponents) {
  const documents = [...new Set(bomComponents.map((component) => component.assetId))].map((assetId, index) => ({
    bomId: `bom-${String(index + 1).padStart(4, '0')}`, assetId, bomType: 'SBOM', specFamily: 'CYCLONEDX', documentFormat: 'JSON',
    sourceType: 'UPLOAD', sourceSystem: index % 2 ? 'github' : 'ci_pipeline', sourceReference: `${assetById.get(assetId).identifier}/sbom.cdx.json`,
    sourceLabel: index % 2 ? 'GitHub dependency graph' : 'CI pipeline upload', documentName: `${assetById.get(assetId).name}.cdx.json`,
    checksumSha256: `${(index + 1).toString(16).padStart(4, '0')}${'ab12cd34ef56'.repeat(5)}`, componentCount: 40 + index * 13,
    evidenceCount: 60 + index * 9, vulnerabilityLinkCount: index * 2, ingestedAt: iso(-2 - index),
  }));
  return {
    documentCount: documents.length, componentCount: bomComponents.length, evidenceCount: bomComponents.length * 2,
    vulnerabilityLinkCount: bomComponents.reduce((total, component) => total + component.cveCount, 0),
    componentsInWorkflow: bomComponents.filter((component) => component.cveCount > 0).length, documents,
    components: bomComponents.slice(0, 8).map((component, index) => ({
      componentId: component.id, bomId: documents[0]?.bomId ?? 'bom-0001', name: component.packageName, version: component.version,
      supplier: component.publisher, purl: component.purl || undefined, cpe: component.cpe23, license: component.license,
      workflowStatus: component.cveCount ? (index % 2 ? 'IN_REMEDIATION' : 'TRIAGE') : undefined, evidenceCount: 2, vulnerabilityCount: component.cveCount,
      sourceSystem: component.sourceSystem, sourceReference: component.sourceReference,
    })),
  };
}

// ── Hosts ───────────────────────────────────────────────────────────────────
const CVE_META = (cveId, index) => ({ severity: SEVERITY_BY_CVE(cveId, index), cvssScore: Number((9.8 - (index % 6) * 0.9).toFixed(1)), epssScore: Number((((Number(cveId.slice(-3)) * 7) % 97) / 100).toFixed(2)) });
let hostDetailCache;
function hostDetails() {
  if (hostDetailCache) return hostDetailCache;
  hostDetailCache = assets.filter((asset) => asset.type === 'HOST').map((asset, hostIndex) => {
    const mine = components.filter((component) => component.assetId === asset.id);
    const software = mine.map((component, index) => ({
      id: `hsw-${component.id}`, inventoryComponentId: component.id, displayName: component.hostName ?? identityById.get(component.identityId).displayName,
      publisher: component.publisher, version: component.version, normalizedPublisher: (component.publisher ?? 'unknown').toLowerCase().replace(/[^a-z0-9]+/g, '_'),
      normalizedProduct: component.packageName, normalizedVersion: component.version, sourceSystem: component.sourceSystem,
      versionEvidence: component.version ? 'package-manager' : undefined, activeInstall: index % 3 !== 2, unlicensedInstall: false,
      installDate: iso(-400 + index * 17), lastScanned: asset.lastInventoryAt, lastUsed: index % 2 ? iso(-index) : undefined,
      discoveryModelPrimaryKey: index % 4 === 0 ? `dm-${component.packageName.replace(/\s+/g, '-')}-${index}` : undefined,
      softwareIdentity: identityById.get(component.identityId).displayName, cpe23: component.cpe23,
      needsVersionReview: !component.version, needsIdentityReview: component.reviewUnmappedSoftware, needsDiscoveryModelReview: component.reviewDiscoveryModel,
      eolSlug: component.eolSlug, eolCycle: component.eolCycle, eolDate: component.eolDate, isEol: component.isEol, eolDaysRemaining: component.eolDaysRemaining,
    }));
    const applicableCves = mine.flatMap((component) => component.cveIds.map((cveId, index) => ({
      stateId: `state-${component.id}-${index}`, vulnerabilityId: `vuln-${cveId}`, externalId: cveId, ...CVE_META(cveId, index),
      packageName: component.packageName, version: component.version, impactState: index === 0 ? 'IMPACTED' : 'UNDER_INVESTIGATION', lastEvaluatedAt: iso(-index * 0.3),
    })));
    const hostFindings = findingRecords.filter((finding) => finding.assetName === asset.name).slice(0, 12).map((finding) => ({
      id: finding.id, displayId: finding.displayId, vulnerabilityId: finding.vulnerabilityId, packageName: finding.packageName, packageVersion: finding.packageVersion,
      severity: finding.severity, status: finding.status, decisionState: finding.decisionState, riskScore: finding.riskScore, confidenceScore: finding.confidenceScore,
      matchedBy: finding.matchedBy, assignedTo: finding.assignedTo, ownerGroup: finding.ownerGroup, creationSource: finding.creationSource,
      dueAt: finding.dueAt, firstObservedAt: finding.firstObservedAt, lastObservedAt: finding.lastObservedAt,
    }));
    const aliases = Array.from({ length: asset.id === PRIMARY_HOST_ID ? 3 : hostIndex === 11 ? 0 : hostIndex % 4 }, (_, index) => ({
      id: `alias-${asset.id}-${index}`, aliasName: [`${asset.name}.corp.example.test`, `ip-10-20-${hostIndex}-${11 + index}.ec2.internal`, `i-0${hostIndex}fa1b2c3d4e5f6${index}`][index],
      sourceSystem: ['servicenow', 'aws_ssm', 'crowdstrike'][index], confidence: index === 2 ? undefined : 0.98 - index * 0.21, firstSeenAt: iso(-120 + index * 10), lastSeenAt: iso(-index),
    }));
    const ssm = hostIndex % 3 !== 2;
    const os = software.map((item) => item.displayName).find((name) => /windows|ubuntu|debian|linux|red hat/i.test(name)) ?? 'Unknown';
    return {
      os,
      host: {
        assetId: asset.id, ciId: `ci-${String(hostIndex + 1).padStart(4, '0')}`, name: asset.name, identifier: asset.identifier, sysId: `0f1e2d3c4b5a69788796a5b4c3d2e1f${hostIndex.toString(16)}`,
        environment: asset.environment, ownerEmail: asset.ownerEmail, managedBy: hostIndex % 2 ? 'priya.raman@example.test' : undefined, department: asset.ownerTeam,
        supportGroup: asset.ownerTeam, assignedTo: hostIndex % 3 ? 'marcus.lee@example.test' : undefined, businessCriticality: asset.businessCriticality, state: asset.state,
        lastInventoryAt: asset.lastInventoryAt, lastCmdbSyncAt: asset.lastCmdbSyncAt, ssmManaged: ssm, ssmPingStatus: ssm ? (hostIndex === 8 ? 'ConnectionLost' : 'Online') : undefined,
        ssmLastPingAt: ssm ? iso(-hostIndex * 0.1) : undefined, ssmInventoryAvailable: ssm, ssmInventoryLastCapturedAt: ssm ? iso(-0.5) : undefined, missingIamInstanceProfile: hostIndex === 9,
        aliasCount: aliases.length, installedSoftwareCount: software.length, openFindingCount: hostFindings.filter((finding) => finding.status === 'OPEN').length,
        totalFindingCount: hostFindings.length, unresolvedReviewCount: software.filter((item) => item.needsVersionReview || item.needsIdentityReview || item.needsDiscoveryModelReview).length,
      },
      bomEvidence: bomEvidenceFor(asset.id === PRIMARY_HOST_ID ? mine : []),
      aliases, software, findings: hostFindings, applicableCves,
    };
  });
  return hostDetailCache;
}
const hostDetailBody = (detail) => { const { os, ...body } = detail; return body; };

// ── Overview / dashboard / EOL / quality ────────────────────────────────────
const activeComponents = () => components.filter((component) => component.componentStatus === 'ACTIVE');

function dashboardBody() {
  const zero = (keys) => Object.fromEntries(keys.map((key) => [key, 0]));
  return {
    assets: assets.length, components: activeComponents().length, openFindings: 41, criticalFindings: 9, openCritical: 9, openHigh: 14, openMedium: 12, openLow: 6,
    averageOpenRiskScore: 7.1, averageOpenConfidenceScore: 0.88, highConfidenceOpenFindings: 33,
    topVulnerabilities: [{ key: 'CVE-2026-31337', count: 6 }, { key: 'CVE-2026-28810', count: 4 }, { key: 'CVE-2026-27455', count: 3 }],
    topInstalledComponents: identities.slice(0, 5).map((identity) => ({ key: identity.displayName, count: identity.componentCount })),
    topAssetsAtRisk: [{ key: 'prod-api-gw-01', count: 9 }, { key: 'billing-core', count: 7 }, { key: 'payments-svc', count: 5 }],
    topVulnerabilityProductIdentities: identities.filter((identity) => identity.openVulnerabilityCount).slice(0, 5).map((identity) => ({ key: identity.displayName, count: identity.openVulnerabilityCount })),
    latestFindings: [],
    noiseReduction: { ...zero(['totalFilteredNotApplicable', 'neverOpenedNotApplicable', 'autoResolvedNotApplicable', 'deferredUnderInvestigation', 'potentialFindingsWithoutCorrelation', 'filteredPercentOfPotential']), categories: [], trendLast30Days: [] },
    csafVexAnalytics: { ...zero(['csafRunsLast30Days', 'csafSuccessfulRunsLast30Days', 'csafPartialFailureRunsLast30Days', 'csafNormalizationSuccessRate', 'csafPartialFailureRate', 'activeVexCoveragePercent', 'activeVexMatchedStateCount', 'activeApplicableAwaitingVexCount', 'activeVexConfirmedImpactedCount', 'activeVexConfirmedNotAffectedCount', 'activeVexNoPatchCount', 'findingsSuppressedByVex', 'suppressedByStaleVex', 'underInvestigationAging']), vexCoverageByProvider: [], staleSuppressionsTrendLast30Days: [] },
    correlationEfficiency: zero(['activeComponents', 'cpeEligibleActiveComponents', 'cpeIneligibleActiveComponents', 'cpeCoveragePercent', 'openFindingsMatchedByCpe', 'openFindingsCpeDirect', 'openFindingsCpeFallback', 'cpeDirectSharePercent', 'cpeFallbackSharePercent', 'averageOpenCpeConfidenceScore', 'cpeFindingsCreatedLast24Hours', 'nonCpeFindingsCreatedLast24Hours']),
  };
}

const applicableSoftware = () => activeComponents().filter((component) => component.cveCount > 0).map((component, index) => ({
  componentId: component.id, assetId: component.assetId, assetName: component.assetName, assetIdentifier: component.assetIdentifier, ecosystem: component.ecosystem,
  packageName: component.packageName, version: component.version ?? '', applicableCveCount: component.cveCount, awaitingVexCveCount: index % 3 === 0 ? 1 : 0,
  vexMatchedCveCount: index % 4 === 1 ? 1 : 0, impactedCveCount: component.impactedCveCount, noPatchCveCount: index % 5 === 2 ? 1 : 0, lastEvaluatedAt: iso(-index * 0.2),
}));

function eolSummary() {
  const active = activeComponents();
  const count = (lifecycle) => active.filter((component) => component.lifecycle === lifecycle).length;
  return { totalTracked: active.length, eolCount: count('eol'), nearEolCount: count('near'), supportedCount: count('supported'), unknownCount: count('unknown') };
}

const qualitySummary = {
  generatedAt: iso(-0.1), totalIssues: 14, criticalIssues: 2, affectsActiveFindingsCount: 5, newIssuesLast24h: 3,
  domainCounts: [{ domain: 'NORMALIZATION', issueCount: 6 }, { domain: 'CORRELATION', issueCount: 3 }, { domain: 'EOL', issueCount: 4 }, { domain: 'VEX', issueCount: 1 }],
};

const springPage = (content, params, fallbackSize = 25) => {
  const size = Number(params.get('size') ?? fallbackSize);
  const number = Number(params.get('page') ?? 0);
  return { content: content.slice(number * size, number * size + size), number, size, totalElements: content.length, totalPages: Math.max(1, Math.ceil(content.length / size)) };
};
const itemPage = (items, params, fallbackSize = 25) => {
  const size = Number(params.get('size') ?? fallbackSize);
  const page = Number(params.get('page') ?? 0);
  return { items: items.slice(page * size, page * size + size), page, size, totalItems: items.length, totalPages: Math.max(1, Math.ceil(items.length / size)) };
};

function narrowComponents(params) {
  const all = (key) => params.getAll(key);
  const lower = (key) => all(key).map((value) => value.toLowerCase());
  const query = (params.get('query') ?? '').toLowerCase();
  return components.filter((component) => {
    if (all('assetType').length && !all('assetType').includes(component.assetType)) return false;
    if (all('componentStatus').length && !all('componentStatus').includes(component.componentStatus)) return false;
    if (lower('sourceSystem').length && !lower('sourceSystem').includes(component.sourceSystem)) return false;
    if (lower('ecosystem').length && !lower('ecosystem').includes(component.ecosystem)) return false;
    if (query && !`${component.packageName} ${component.assetName} ${component.purl} ${component.version ?? ''}`.toLowerCase().includes(query)) return false;
    return true;
  });
}

// ── BOM ─────────────────────────────────────────────────────────────────────
const bomAssets = () => assets.filter((asset) => asset.type !== 'HOST');
const riskLevel = (critical, high) => (critical ? 'CRITICAL' : high ? 'HIGH' : 'LOW');
const cveSplit = (cveIds) => cveIds.reduce((counts, cveId, index) => { counts[SEVERITY_BY_CVE(cveId, index).toLowerCase()] += 1; return counts; }, { critical: 0, high: 0, medium: 0, low: 0 });

const bomComponents = () => components.filter((component) => component.assetType !== 'HOST').map((component, index) => {
  const split = cveSplit(component.cveIds);
  return {
    componentId: component.id, packageName: component.packageName, version: component.version ?? null, purl: component.purl || null, ecosystem: component.ecosystem,
    license: component.license ?? null, assetId: component.assetId, assetName: component.assetName,
    bomTypes: component.assetType === 'APPLICATION' && index % 4 === 0 ? ['SBOM', 'AIBOM'] : ['SBOM'],
    isEol: component.isEol === true, eolDate: component.eolDate ?? null, criticalCveCount: split.critical, highCveCount: split.high, mediumCveCount: split.medium, lowCveCount: split.low,
    totalCveCount: component.cveCount, correlationState: component.cveCount ? 'APPLICABLE' : ['NOT_APPLICABLE', 'UNKNOWN', 'UNCHECKED'][index % 3],
    riskLevel: riskLevel(split.critical, split.high), findingCount: Math.max(0, component.cveCount - 1), criticalFindingCount: split.critical ? 1 : 0, highFindingCount: split.high ? 1 : 0,
    bomEvidenceState: [null, 'SUPPORTED', 'SUPPORTED', 'CONFLICTING', 'WITHDRAWN', 'LEGACY_UNKNOWN'][index % 6],
  };
});

const applicationRisk = () => bomAssets().map((asset, index) => {
  const mine = bomComponents().filter((component) => component.assetId === asset.id);
  const sum = (key) => mine.reduce((total, component) => total + component[key], 0);
  const critical = sum('criticalCveCount');
  const high = sum('highCveCount');
  return {
    assetId: asset.id, assetName: asset.name, assetIdentifier: asset.identifier, businessCriticality: asset.businessCriticality, bomTypes: index % 3 === 0 ? ['SBOM', 'AIBOM'] : ['SBOM'],
    totalComponents: mine.length, vulnerableComponents: mine.filter((component) => component.totalCveCount).length, eolComponents: mine.filter((component) => component.isEol).length,
    criticalCveCount: critical, highCveCount: high, mediumCveCount: sum('mediumCveCount'), lowCveCount: sum('lowCveCount'), totalCveCount: sum('totalCveCount'),
    riskScore: Math.min(100, critical * 18 + high * 9 + sum('mediumCveCount') * 3), riskLevel: riskLevel(critical, high),
    lastIngestedAt: index === 4 ? null : iso(-index * 0.8), findingCount: sum('findingCount'),
  };
});

const bomComponentDetail = (summary) => {
  const component = components.find((candidate) => candidate.id === summary.componentId);
  return {
    ...summary, packageGroup: component.packageGroup ?? null, scope: 'required', normalizedName: component.normalizedName, eolSlug: component.eolSlug ?? null,
    eolCycle: component.eolCycle ?? null, eolSupportEndDate: component.eolDate ?? null, supportPhase: component.lifecycle === 'eol' ? 'END_OF_LIFE' : component.lifecycle === 'near' ? 'SECURITY_ONLY' : component.lifecycle === 'supported' ? 'ACTIVE' : null,
    eolCheckedAt: component.eolSlug ? iso(-1) : null, ingestedAt: iso(-4), lastObservedAt: component.lastObservedAt, assetIdentifier: component.assetIdentifier, assetType: component.assetType,
    cves: component.cveIds.map((cveId, index) => ({ cveId: `vuln-${cveId}`, externalId: cveId, severity: SEVERITY_BY_CVE(cveId, index), title: index ? null : 'Synthetic advisory title for fixture review', applicabilityState: 'APPLICABLE', epssScore: CVE_META(cveId, index).epssScore, cvssScore: CVE_META(cveId, index).cvssScore })),
    eolReleases: component.eolSlug ? [
      { cycle: component.eolCycle, releaseDate: isoDate(-900), eolDate: component.eolDate ?? null, supportEndDate: component.eolDate ?? null, latestVersion: component.version ?? null, latestReleaseDate: isoDate(-60), isEol: component.isEol === true, isLts: true },
      { cycle: 'next', releaseDate: isoDate(-200), eolDate: isoDate(900), supportEndDate: null, latestVersion: 'latest', latestReleaseDate: isoDate(-10), isEol: false, isLts: false },
    ] : [],
  };
};

const BOM_SOURCES = [['UPLOAD', 'ci_pipeline'], ['GITHUB', 'github'], ['REGISTRY', 'ecr_scan'], ['UPLOAD', 'manual']];
const bomInventory = Array.from({ length: 56 }, (_, index) => {
  const asset = bomAssets()[index % bomAssets().length];
  const [sourceType, sourceSystem] = BOM_SOURCES[index % BOM_SOURCES.length];
  const spdx = index % 5 === 3;
  return {
    id: `bom-${String(index + 1).padStart(4, '0')}`, assetId: asset.id, bomType: index % 9 === 4 ? 'AIBOM' : index % 11 === 7 ? 'CBOM' : 'SBOM',
    format: spdx ? 'SPDX' : 'CycloneDX', formatVersion: spdx ? '2.3' : '1.5', specFamily: spdx ? 'SPDX' : 'CYCLONEDX', documentFormat: index % 7 === 6 ? 'XML' : 'JSON',
    serialNumber: `urn:uuid:3e671687-395b-41f5-a30f-${String(index + 1).padStart(12, '0')}`, supplier: index % 6 === 5 ? '' : 'Fixture Org Build System',
    sourceMethod: sourceType === 'GITHUB' ? 'DEPENDENCY_GRAPH' : 'PUSH', sourceType, sourceSystem,
    sourceUrl: sourceType === 'GITHUB' ? `https://github.com/fixture-org/${asset.name}/dependency-graph/sbom` : '',
    supportLevel: index % 13 === 12 ? 'PARTIAL' : 'FULL', supported: index % 13 !== 12, componentCount: 20 + (index * 17) % 140, evidenceCount: 30 + (index * 11) % 90,
    vulnerabilityLinkCount: (index * 3) % 12, correlatedComponentCount: (index * 5) % 40, status: index % 10 === 9 ? 'SUPERSEDED' : index % 17 === 16 ? 'FAILED' : 'ACTIVE',
    ingestedAt: iso(-index * 0.6), ingestedBy: index % 2 ? 'ci-bot@example.test' : 'fixture.analyst@example.test',
  };
});

const bomDashboard = () => {
  const breakdown = (key) => Object.entries(bomInventory.reduce((acc, item) => ({ ...acc, [item[key]]: (acc[item[key]] ?? 0) + 1 }), {})).map(([value, count]) => ({ key: value, label: value.replace(/_/g, ' '), count }));
  return {
    documentCount: bomInventory.length, componentCount: bomInventory.reduce((total, item) => total + item.componentCount, 0), evidenceCount: bomInventory.reduce((total, item) => total + item.evidenceCount, 0),
    vulnerabilityLinkCount: bomInventory.reduce((total, item) => total + item.vulnerabilityLinkCount, 0), correlatedComponentCount: 612, activeWorkflowCount: 7, openRemediationCount: 4, sourceSystemCount: 4,
    bomTypes: breakdown('bomType'), specFamilies: breakdown('specFamily'), sourceSystems: breakdown('sourceSystem'),
    workflowStatuses: [{ key: 'TRIAGE', label: 'Triage', count: 9 }, { key: 'IN_REMEDIATION', label: 'In remediation', count: 4 }, { key: 'ACCEPTED_RISK', label: 'Accepted risk', count: 0 }],
  };
};

const bomDetail = (item) => {
  const mine = bomComponents().filter((component) => component.assetId === item.assetId);
  return {
    ...item, sourceReference: `${assetById.get(item.assetId).identifier}/sbom.cdx.json`, checksumSha256: `${item.id.replace('bom-', '')}${'e3b0c44298fc1c149afbf4c8996fb924'.repeat(2)}`.slice(0, 64),
    inspection: { format: item.format, formatVersion: item.formatVersion, specFamily: item.specFamily, documentFormat: item.documentFormat, supportLevel: item.supportLevel, supported: item.supported,
      warnings: item.supported ? [] : ['Component hashes missing for 14 entries', 'Dependency graph truncated at depth 6'] },
    workflowSummary: [{ workflowStatus: 'TRIAGE', componentCount: 3 }, { workflowStatus: 'IN_REMEDIATION', componentCount: 1 }],
    components: mine.map((component, index) => ({
      id: component.componentId, name: component.packageName, version: component.version ?? '', purl: component.purl ?? '', cpe: index % 2 ? '' : `cpe:2.3:a:fixture:${component.packageName.replace(/\s+/g, '_')}:${component.version ?? '*'}:*:*:*:*:*:*:*`,
      license: component.license ?? '', supplier: index % 3 ? 'Fixture Supplier' : '', componentType: 'library', category: component.ecosystem ?? 'unknown',
      workflowStatus: component.totalCveCount ? 'TRIAGE' : 'NONE', vulnerabilityCount: component.totalCveCount, evidenceCount: 2, active: true,
    })),
  };
};

const bomLineage = (item) => [0, 1, 2].map((revision) => ({
  id: revision === 0 ? item.id : `${item.id}-r${revision}`, previousBomId: revision === 2 ? null : `${item.id}-r${revision + 1}`, supersededBy: revision === 0 ? null : revision === 1 ? item.id : `${item.id}-r1`,
  bomType: item.bomType, status: revision === 0 ? item.status : 'SUPERSEDED', format: item.format, formatVersion: item.formatVersion, specFamily: item.specFamily, documentFormat: item.documentFormat,
  sourceType: item.sourceType, sourceSystem: item.sourceSystem, sourceReference: `${assetById.get(item.assetId).identifier}/sbom.cdx.json#rev${3 - revision}`,
  checksumSha256: `${revision}${'5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef'}`.slice(0, 64), componentCount: item.componentCount - revision * 4, ingestedAt: iso(-revision * 14 - 1),
}));

// ── AI inventory ────────────────────────────────────────────────────────────
// [id, type, nativeKind, name, provider, critical, high, total, policiesFailed, policiesTotal, extra]
const AI_CORE = [
  [PRIMARY_AI_ASSET_ID, 'AI_AGENT', 'AWS_BEDROCK_AGENT', 'claims-triage-agent', 'AWS', 1, 2, 5, 3, 9, { deployment: 'SERVED', criticality: 'CRITICAL', owner: 'Claims Engineering' }],
  ['ai-agentver-claims-triage-v3', 'AI_AGENT_VERSION', 'AWS_BEDROCK_AGENT_VERSION', 'claims-triage-agent:3', 'AWS', 0, 1, 1, 1, 6, {}],
  ['ai-agentver-claims-triage-v2', 'AI_AGENT_VERSION', 'AWS_BEDROCK_AGENT_VERSION', 'claims-triage-agent:2', 'AWS', 0, 0, 0, 0, 6, { inactive: true }],
  ['ai-model-claims-text', 'AI_MODEL', 'AWS_BEDROCK_MODEL', 'fixture-text-model-v2 (provisioned)', 'AWS', 1, 0, 2, 1, 5, { criticality: 'HIGH' }],
  ['ai-prompt-claims-summary', 'AI_PROMPT', 'AWS_BEDROCK_PROMPT', 'claims-summary-prompt', 'AWS', 0, 0, 1, 0, 3, {}],
  ['ai-guardrail-claims', 'AI_GUARDRAIL', 'AWS_BEDROCK_GUARDRAIL', 'claims-pii-guardrail', 'AWS', 0, 1, 1, 1, 4, {}],
  ['ai-kb-claims-docs', 'KNOWLEDGE_BASE', 'AWS_BEDROCK_KNOWLEDGE_BASE', 'claims-policy-documents', 'AWS', 1, 1, 3, 2, 5, { pii: 'SCANNED_PII_FOUND', sourceType: 'S3', publicContentAccess: 'false' }],
  ['ai-ds-claims-s3', 'DATA_SOURCE', 'AWS_BEDROCK_DATA_SOURCE', 'claims-docs-s3-source', 'AWS', 0, 0, 0, 0, 2, { pii: 'SCANNED_CLEAN', sourceType: 'S3', publicContentAccess: 'false' }],
  ['ai-store-claims-vectors', 'DATA_STORE', 'AWS_OPENSEARCH_SERVERLESS_COLLECTION', 'claims-vector-collection', 'AWS', 0, 1, 1, 1, 3, { pii: 'NOT_SCANNED', storeType: 'OPENSEARCH_SERVERLESS' }],
  ['ai-mcp-gw-tools', 'MCP_GATEWAY', 'AWS_AGENTCORE_GATEWAY', 'claims-tools-gateway', 'AWS', 0, 1, 1, 1, 4, { endpointHost: 'gw-a1b2c3.gateway.bedrock-agentcore.us-east-1.amazonaws.com', endpointExposure: 'PUBLIC_NETWORK_REACHABLE', inboundAuthType: 'OAUTH', status: 'READY' }],
  ['ai-mcp-target-ticketing', 'MCP_TARGET', 'AWS_AGENTCORE_GATEWAY_TARGET', 'ticketing-lambda-target', 'AWS', 0, 0, 0, 0, 2, { endpointHost: null, endpointExposure: 'UNKNOWN', configuredAuthType: 'NONE', status: 'SYNCHRONIZE_UNSUCCESSFUL' }],
  ['ai-agent-hr-helpdesk', 'AI_AGENT', 'MICROSOFT_COPILOT', 'hr-helpdesk-copilot', 'MICROSOFT_COPILOT', 0, 1, 2, 1, 5, { deployment: 'NOT_CURRENTLY_SERVED', owner: null }],
  ['ai-tool-copilot-ticket', 'AI_TOOL', 'MICROSOFT_COPILOT_TOOL', 'create-ticket-action', 'MICROSOFT_COPILOT', 0, 0, 0, 0, 2, {}],
  ['ai-kb-sharepoint-hr', 'KNOWLEDGE_BASE', 'MICROSOFT_COPILOT_KNOWLEDGE_SOURCE', 'hr-policies-sharepoint', 'MICROSOFT_COPILOT', 0, 1, 1, 1, 3, { pii: 'LOOKUP_FAILED', sourceType: 'SHAREPOINT', publicContentAccess: 'true' }],
  ['ai-agent-foundry-support', 'AI_AGENT', 'AZURE_FOUNDRY_AGENTS', 'support-foundry-agent', 'AZURE', 0, 0, 1, 0, 4, { deployment: 'UNVERIFIED' }],
  ['ai-model-azure-chat', 'AI_MODEL', 'AZURE_FOUNDRY_DEPLOYMENTS', 'chat-deployment-eastus2', 'AZURE', 0, 1, 1, 1, 5, {}],
  ['ai-rai-default', 'AI_GUARDRAIL', 'AZURE_RAI_POLICIES', 'Microsoft.DefaultV2', 'AZURE', 0, 1, 1, 1, 3, {}],
  ['ai-search-hr-index', 'SEARCH_INDEX', 'AZURE_AI_SEARCH_INDEX', 'hr-handbook-index', 'AZURE', 0, 0, 0, 0, 2, { pii: 'UNKNOWN', sourceType: 'WEB', publicContentAccess: 'true' }],
  ['ai-mcp-server-files', 'MCP_SERVER', 'AZURE_FOUNDRY_MCP_SERVER', 'files-mcp-server', 'AZURE', 0, 0, 1, 0, 2, { endpointHost: 'files-mcp.fixture-tenant.example.test', endpointExposure: 'EXTERNAL_ENDPOINT', configuredAuthType: 'CUSTOM_HEADER', status: 'READY' }],
  ['ai-runtime-research', 'AI_AGENT', 'AWS_AGENTCORE_RUNTIME', 'research-assistant-runtime', 'AWS', 0, 0, 0, 0, 3, { deployment: 'SERVED' }],
  ['ai-identity-foundry-mi', 'SUPPORTING_RESOURCE', 'AZURE_IDENTITY', 'foundry-project-managed-identity', 'AZURE', 0, 1, 1, 1, 2, {}],
  ['ai-other-sagemaker-endpoint', 'OTHER_AI_ARTIFACT', 'AWS_SAGEMAKER_ENDPOINT', 'fraud-scoring-endpoint', 'AWS', 0, 0, 0, 0, 0, {}],
];

const AI_PAD_KINDS = [
  ['AI_GUARDRAIL', 'AWS_BEDROCK_GUARDRAIL', 'guardrail', 'AWS'], ['SUPPORTING_RESOURCE', 'AZURE_RBAC_GLOBAL', 'rbac-assignment', 'AZURE'],
  ['AI_PROMPT', 'AZURE_FOUNDRY_PROMPT', 'prompt', 'AZURE'], ['KNOWLEDGE_BASE', 'AWS_BEDROCK_KNOWLEDGE_BASE', 'kb', 'AWS'],
  ['MCP_TARGET', 'AWS_AGENTCORE_GATEWAY_TARGET', 'mcp-target', 'AWS'], ['OTHER_AI_ARTIFACT', 'AWS_SAGEMAKER_NOTEBOOK', 'notebook', 'AWS'],
  ['AI_AGENT', 'AWS_BEDROCK_AGENT', 'agent', 'AWS'],
];
const AI_PAD = Array.from({ length: 40 }, (_, index) => {
  const [type, nativeKind, label, provider] = AI_PAD_KINDS[index % AI_PAD_KINDS.length];
  const critical = index % 13 === 0 ? 1 : 0;
  const high = index % 5 === 0 ? 1 : 0;
  return [`ai-${label}-${String(index + 1).padStart(2, '0')}`, type, nativeKind, `${label}-${['payments', 'support', 'claims', 'marketing', 'risk'][index % 5]}-${String(index + 1).padStart(2, '0')}`, provider,
    critical, high, critical + high + (index % 3 === 0 ? 1 : 0), critical + high, 2 + (index % 4),
    type === 'AI_AGENT' ? { deployment: ['SERVED', 'NOT_CURRENTLY_SERVED', 'UNVERIFIED'][index % 3] } : type === 'KNOWLEDGE_BASE'
      ? { pii: ['SCANNED_CLEAN', 'NOT_SCANNED', 'NOT_APPLICABLE'][index % 3], sourceType: ['S3', 'CONFLUENCE', 'SALESFORCE', 'WEB'][index % 4], publicContentAccess: index % 2 ? 'false' : 'true' }
      : type === 'MCP_TARGET' ? { endpointHost: `target-${index}.fixture.example.test`, endpointExposure: index % 2 ? 'EXTERNAL_ENDPOINT' : 'UNKNOWN', configuredAuthType: ['OAUTH', 'MANAGED_IDENTITY', 'NONE'][index % 3], status: index % 3 ? 'READY' : 'FAILED' }
        : index % 6 === 0 ? { inactive: true } : {}];
});

const deployment = (status, id) => status ? {
  status, reasonCode: status === 'SERVED' ? 'VERIFIED_SERVING_ROUTE' : status === 'NOT_CURRENTLY_SERVED' ? 'NO_ALIAS_ROUTE' : 'PERMISSION_DENIED',
  observedAt: status === 'UNVERIFIED' ? null : iso(-0.2), expiresAt: status === 'UNVERIFIED' ? null : iso(1),
  evidenceReferences: status === 'SERVED' ? [{ family: 'BEDROCK_AGENT_ALIAS', scopeId: `scope-${id}`, runId: 'run-ai-0042', observedAt: iso(-0.2), collectionStatus: 'COMPLETE', reasonCode: 'VERIFIED_SERVING_ROUTE', routeIds: [`${id === PRIMARY_AI_ASSET_ID ? 'ai-agentver-claims-triage-v3' : id}`] }] : [],
  lastVerifiedObservation: status === 'SERVED' ? null : { status: 'SERVED', reasonCode: 'VERIFIED_SERVING_ROUTE', observedAt: iso(-9), expiresAt: iso(-8) },
} : undefined;

const arnFor = (provider, nativeKind, id) => provider === 'AWS'
  ? `arn:aws:${nativeKind.includes('SAGEMAKER') ? 'sagemaker' : nativeKind.includes('OPENSEARCH') ? 'aoss' : 'bedrock'}:us-east-1:${AWS_ACCOUNT}:${nativeKind.toLowerCase().replace(/^aws_(bedrock_|agentcore_)?/, '').replace(/_/g, '-')}/${id.replace(/^ai-/, '')}-${'a1b2c3d4e5'}`
  : provider === 'AZURE'
    ? `/subscriptions/${AZURE_SUB}/resourceGroups/rg-ai-fixture/providers/Microsoft.CognitiveServices/accounts/foundry-fixture/${nativeKind.toLowerCase().replace(/^azure_/, '')}/${id.replace(/^ai-/, '')}`
    : `copilot://environments/Default-00000000-0000-0000-0000-000000000001/bots/${id.replace(/^ai-/, '')}`;

export const aiArtifacts = [...AI_CORE, ...AI_PAD].map(([id, artifactType, nativeKind, name, provider, critical, high, total, policiesFailed, policiesTotal, extra], index) => ({
  summary: { id, name, nativeKind, provider, accountId: provider === 'AWS' ? AWS_ACCOUNT : provider === 'AZURE' ? AZURE_SUB : 'Default-Environment', region: provider === 'MICROSOFT_COPILOT' ? 'global' : provider === 'AZURE' ? 'eastus2' : index % 4 === 3 ? 'eu-west-1' : 'us-east-1',
    criticalFindings: critical, highFindings: high, totalFindings: total, policiesFailed, policiesTotal, deployment: deployment(extra.deployment, id) },
  artifact: {
    deployment: deployment(extra.deployment, id) ?? null, id, provider, providerResourceId: arnFor(provider, nativeKind, id), artifactType, nativeKind, name,
    accountId: provider === 'AWS' ? AWS_ACCOUNT : provider === 'AZURE' ? AZURE_SUB : 'Default-Environment', region: provider === 'MICROSOFT_COPILOT' ? 'global' : provider === 'AZURE' ? 'eastus2' : index % 4 === 3 ? 'eu-west-1' : 'us-east-1',
    active: !extra.inactive,
    attributes: {
      ...(artifactType === 'AI_AGENT' ? { foundationModel: 'fixture-text-model-v2', idleSessionTtlSeconds: 600, dataSourceAccessCount: index === 0 ? 2 : 0 } : {}),
      ...(artifactType === 'AI_MODEL' ? { modelVersion: '2.0.1', throughputUnits: index % 2 ? null : 4, customizationType: 'FINE_TUNED' } : {}),
      ...(extra.sourceType ? { sourceType: extra.sourceType, aclSupport: extra.sourceType === 'SHAREPOINT' ? 'INHERITED' : 'NOT_SUPPORTED', retrievalMode: 'HYBRID', publicContentAccess: extra.publicContentAccess } : {}),
      ...(extra.storeType ? { storeType: extra.storeType, backingStore: 'opensearch-serverless' } : {}),
      ...('endpointExposure' in extra ? { endpointHost: extra.endpointHost, endpointExposure: extra.endpointExposure, configuredAuthType: extra.configuredAuthType, inboundAuthType: extra.inboundAuthType, status: extra.status, lastSynchronizedAt: extra.status === 'READY' ? iso(-0.3) : null } : {}),
      tags: index % 3 === 0 ? [{ key: 'cost-center', value: 'CC-4410' }] : [],
    },
    ownerName: extra.owner === null ? null : extra.owner ?? (index % 4 === 1 ? null : 'AI Platform'), ownerState: extra.owner === null || index % 4 === 1 ? 'UNOWNED' : extra.owner ? 'CONFIRMED' : 'INFERRED',
    ownerSource: extra.owner === null || index % 4 === 1 ? null : extra.owner ? 'MANUAL' : 'RESOURCE_TAG', ownerConfidence: extra.owner ? 1 : index % 4 === 1 ? null : 0.72,
    ownerConfidenceMethod: index % 4 === 1 ? null : 'tag-heuristic', ownerConfidenceMethodVersion: index % 4 === 1 ? null : '1', businessCriticality: extra.criticality ?? (index % 3 ? null : 'MEDIUM'),
    environment: index % 5 === 4 ? null : 'production', firstObservedAt: iso(-90 + index), lastObservedAt: iso(-(index % 7) * 0.25),
    piiScanStatus: extra.pii ?? 'NOT_APPLICABLE', piiSource: extra.pii?.startsWith('SCANNED') ? (provider === 'AWS' ? 'AWS_MACIE' : 'AZURE_PURVIEW') : null,
    piiInfoTypes: extra.pii === 'SCANNED_PII_FOUND' ? ['EMAIL_ADDRESS', 'US_SOCIAL_SECURITY_NUMBER', 'MEDICAL_RECORD_NUMBER'] : [], piiFindingCount: extra.pii === 'SCANNED_PII_FOUND' ? 37 : 0,
    piiLastScannedAt: extra.pii?.startsWith('SCANNED') ? iso(-2) : null,
    attachmentState: index === 0 ? 'ROOT' : artifactType === 'OTHER_AI_ARTIFACT' ? 'STANDALONE_OPTIONAL' : index % 9 === 8 ? 'UNATTACHED_REQUIRED' : 'ATTACHED',
    systemIds: index < 11 ? ['system-claims'] : index < 15 ? ['system-hr'] : [],
  },
}));
const aiById = new Map(aiArtifacts.map((entry) => [entry.artifact.id, entry]));

const AI_EDGES = [
  [PRIMARY_AI_ASSET_ID, 'ACTIVE_VERSION', 'ai-agentver-claims-triage-v3'],
  ['ai-agentver-claims-triage-v3', 'VERSION_OF', PRIMARY_AI_ASSET_ID],
  ['ai-agentver-claims-triage-v2', 'VERSION_OF', PRIMARY_AI_ASSET_ID],
  ['ai-agentver-claims-triage-v3', 'USES_MODEL', 'ai-model-claims-text'],
  ['ai-agentver-claims-triage-v3', 'USES_PROMPT', 'ai-prompt-claims-summary'],
  [PRIMARY_AI_ASSET_ID, 'USES_GUARDRAIL', 'ai-guardrail-claims'],
  [PRIMARY_AI_ASSET_ID, 'USES_KNOWLEDGE_BASE', 'ai-kb-claims-docs'],
  ['ai-kb-claims-docs', 'HAS_DATA_SOURCE', 'ai-ds-claims-s3'],
  ['ai-kb-claims-docs', 'STORES_IN', 'ai-store-claims-vectors'],
  [PRIMARY_AI_ASSET_ID, 'USES_TOOL', 'ai-mcp-gw-tools'],
  ['ai-mcp-gw-tools', 'HAS_TARGET', 'ai-mcp-target-ticketing'],
  ['ai-agent-hr-helpdesk', 'USES_TOOL', 'ai-tool-copilot-ticket'],
  ['ai-agent-hr-helpdesk', 'USES_KNOWLEDGE_BASE', 'ai-kb-sharepoint-hr'],
  ['ai-agent-foundry-support', 'USES_MODEL', 'ai-model-azure-chat'],
  ['ai-agent-foundry-support', 'USES_GUARDRAIL', 'ai-rai-default'],
  ['ai-agent-foundry-support', 'USES_KNOWLEDGE_BASE', 'ai-search-hr-index'],
  ['ai-agent-foundry-support', 'USES_TOOL', 'ai-mcp-server-files'],
  ['ai-agent-foundry-support', 'ASSUMES_IDENTITY', 'ai-identity-foundry-mi'],
].map(([source, relationshipType, target], index) => ({
  id: `edge-${index + 1}`, relationshipType, sourceArtifactId: source, sourceName: aiById.get(source).artifact.name,
  targetArtifactId: target, targetName: aiById.get(target).artifact.name, attributes: index === 6 ? { retrievalConfig: 'top_k=8' } : {},
}));

function aiGraph(rootId, depth) {
  const seen = new Set([rootId]);
  let frontier = [rootId];
  for (let hop = 0; hop < depth; hop += 1) {
    const next = [];
    AI_EDGES.forEach((edge) => {
      [[edge.sourceArtifactId, edge.targetArtifactId], [edge.targetArtifactId, edge.sourceArtifactId]].forEach(([from, to]) => {
        if (frontier.includes(from) && !seen.has(to)) { seen.add(to); next.push(to); }
      });
    });
    frontier = next;
  }
  return { nodes: [...seen].map((id) => aiById.get(id).artifact), edges: AI_EDGES.filter((edge) => seen.has(edge.sourceArtifactId) && seen.has(edge.targetArtifactId)), truncated: false };
}

const AGENT_KINDS = ['AWS_BEDROCK_AGENT', 'AWS_AGENTCORE_RUNTIME', 'AZURE_FOUNDRY_AGENTS', 'AZURE_CLASSIC_FOUNDRY_AGENTS', 'MICROSOFT_COPILOT'];
function narrowAiSummaries(params) {
  const list = (key) => (params.get(key) ?? '').split(',').filter(Boolean);
  const search = (params.get('search') ?? '').toLowerCase();
  const severity = params.get('severity');
  return aiArtifacts.filter(({ summary, artifact }) => {
    if (params.get('artifactType') && artifact.artifactType !== params.get('artifactType')) return false;
    if (params.get('provider') && summary.provider !== params.get('provider')) return false;
    if (params.get('subscription') && summary.accountId !== params.get('subscription')) return false;
    if (list('nativeKind').length && !list('nativeKind').includes(summary.nativeKind)) return false;
    if (list('excludeNativeKinds').includes(summary.nativeKind)) return false;
    if (list('excludeArtifactTypes').includes(artifact.artifactType)) return false;
    if (params.get('inventoryView') === 'AGENTS' && !AGENT_KINDS.includes(summary.nativeKind)) return false;
    if (params.get('inventoryView') === 'OTHERS' && artifact.artifactType === 'AI_AGENT_VERSION') return false;
    if (severity === 'CRITICAL' && !summary.criticalFindings) return false;
    if (severity === 'HIGH' && !summary.highFindings) return false;
    if ((severity === 'MEDIUM' || severity === 'LOW') && summary.totalFindings - summary.criticalFindings - summary.highFindings <= 0) return false;
    if (search && !summary.name.toLowerCase().includes(search)) return false;
    return true;
  });
}

const aiPage = (items, params) => {
  const size = Number(params.get('size') ?? 50);
  const page = Number(params.get('page') ?? 0);
  return { items: items.slice(page * size, page * size + size), page, size, total: items.length };
};

function aiInventoryList(kind, params) {
  const types = kind === 'mcp' ? ['MCP_GATEWAY', 'MCP_TARGET', 'MCP_SERVER'] : ['KNOWLEDGE_BASE', 'DATA_SOURCE', 'DATA_STORE', 'SEARCH_INDEX'];
  const filter = (key, read) => !params.get(key) || read() === params.get(key);
  const items = aiArtifacts.map((entry) => entry.artifact).filter((artifact) => types.includes(artifact.artifactType)
    && filter('provider', () => artifact.provider)
    && filter(kind === 'mcp' ? 'role' : 'kind', () => artifact.artifactType)
    && filter('active', () => String(artifact.active))
    && (kind === 'mcp'
      ? filter('authenticationType', () => artifact.attributes.configuredAuthType ?? artifact.attributes.inboundAuthType) && filter('endpointExposure', () => artifact.attributes.endpointExposure) && filter('synchronizationStatus', () => artifact.attributes.status)
      : filter('sourceType', () => artifact.attributes.sourceType) && filter('sensitivity', () => artifact.piiScanStatus) && filter('publicContentAccess', () => artifact.attributes.publicContentAccess)));
  return aiPage(items, params);
}

function aiSummary() {
  const tally = (read) => aiArtifacts.reduce((acc, entry) => { const key = read(entry); acc[key] = (acc[key] ?? 0) + 1; return acc; }, {});
  return {
    logicalAgentCount: aiArtifacts.filter(({ summary }) => AGENT_KINDS.includes(summary.nativeKind)).length,
    artifactCounts: tally(({ artifact }) => artifact.artifactType), nativeKindCounts: tally(({ summary }) => summary.nativeKind), providerCounts: tally(({ summary }) => summary.provider),
    openFindings: aiArtifacts.reduce((total, { summary }) => total + summary.totalFindings, 0), incompleteScopes: 3, lastCompleteSnapshotAt: iso(-0.4),
  };
}

function severityGrid() {
  const rows = new Map();
  aiArtifacts.forEach(({ summary }) => {
    const row = rows.get(summary.nativeKind) ?? { nativeKind: summary.nativeKind, critical: 0, high: 0, medium: 0, low: 0, total: 0 };
    const other = summary.totalFindings - summary.criticalFindings - summary.highFindings;
    row.critical += summary.criticalFindings ? 1 : 0;
    row.high += summary.highFindings ? 1 : 0;
    row.medium += other > 0 && summary.policiesTotal % 2 === 0 ? 1 : 0;
    row.low += other > 0 && summary.policiesTotal % 2 === 1 ? 1 : 0;
    row.total = row.critical + row.high + row.medium + row.low;
    rows.set(summary.nativeKind, row);
  });
  return { rows: [...rows.values()].filter((row) => row.total > 0) };
}

const topRisk = (limit) => aiArtifacts.map(({ summary }) => ({
  id: summary.id, name: summary.name, nativeKind: summary.nativeKind, provider: summary.provider, accountId: summary.accountId,
  criticalCount: summary.criticalFindings, highCount: summary.highFindings, mediumCount: Math.max(0, summary.totalFindings - summary.criticalFindings - summary.highFindings), lowCount: 0,
  score: summary.criticalFindings * 5 + summary.highFindings * 3 + summary.totalFindings,
})).filter((item) => item.score > 0).sort((left, right) => right.score - left.score).slice(0, limit);

const aiCoverage = {
  runId: 'run-ai-0042', coverageEpochId: 'epoch-2026-10-24', authoritativeScopeHeads: 18, currentArtifacts: aiArtifacts.length, applicablePublished: 41, required: 12,
  tenantEnabled: 33, preview: 4, tenantDisabled: 4, evidenceReady: 29, evaluatedPass: 188, evaluatedFail: 23, noDecision: 9, notApplicable: 140, stale: 2, unsupported: 5,
  decisionReachabilityPercent: 81.4, ownerFacingDecisionReachabilityPercent: 76.2, artifactsFailing: aiArtifacts.filter(({ summary }) => summary.policiesFailed > 0).length,
};

const aiRuns = [
  { id: 'run-ai-0042', status: 'COMPLETE', collectionStatus: 'COMPLETE', assessmentStatus: 'COMPLETE', assessedSubjects: aiArtifacts.length, failedPolicies: 0, recordsFetched: 1284, recordsFailed: 0, startedAt: iso(-0.45), completedAt: iso(-0.4), errorMessage: null },
  { id: 'run-ai-0041', status: 'PARTIAL', collectionStatus: 'PARTIAL', assessmentStatus: 'PARTIAL', assessedSubjects: 51, failedPolicies: 2, recordsFetched: 1190, recordsFailed: 37, startedAt: iso(-1.45), completedAt: iso(-1.4), errorMessage: 'AccessDenied on 3 scopes (bedrock-agentcore:ListGateways)' },
  { id: 'run-ai-0040', status: 'FAILED', collectionStatus: 'FAILED', assessmentStatus: 'FAILED', assessedSubjects: 0, failedPolicies: 0, recordsFetched: 0, recordsFailed: 0, startedAt: iso(-2.45), completedAt: iso(-2.44), errorMessage: 'Role could not be assumed (fixture)' },
];

const posture = (id) => ({
  artifactId: id,
  controls: (aiById.get(id)?.summary.policiesTotal ?? 0) === 0 ? [] : [
    { policyId: 'policy.aws.2', selection: 'ENABLED', evidenceReadiness: 'READY', decision: 'FAIL', missingEvidenceJson: '[]' },
    { policyId: 'policy.aws.3', selection: 'ENABLED', evidenceReadiness: 'READY', decision: 'PASS', missingEvidenceJson: '[]' },
    { policyId: 'policy.azure.1', selection: 'PREVIEW', evidenceReadiness: 'MISSING_EVIDENCE', decision: 'NO_DECISION', missingEvidenceJson: '["guardrailConfiguration"]' },
  ],
  exposures: id === PRIMARY_AI_ASSET_ID ? [{ id: 'exposure-1', title: 'Public agent → knowledge base', severity: 'CRITICAL', priority: 92 }] : [],
});

const agentVersions = (id) => AI_EDGES.filter((edge) => edge.targetArtifactId === id && edge.relationshipType === 'VERSION_OF').map((edge) => ({
  id: edge.sourceArtifactId, name: edge.sourceName, nativeKind: aiById.get(edge.sourceArtifactId).summary.nativeKind,
  definitionVersion: AI_EDGES.some((candidate) => candidate.sourceArtifactId === id && candidate.relationshipType === 'ACTIVE_VERSION' && candidate.targetArtifactId === edge.sourceArtifactId),
  servedVersion: edge.sourceArtifactId.endsWith('v3'), lastObservedAt: iso(-0.3),
}));

const baselines = (id) => id === PRIMARY_AI_ASSET_ID ? [{ artifactId: id, digestKind: 'AGENT_DEFINITION', approvalStatus: 'APPROVED', approvedBy: 'fixture.analyst@example.test', approvedAt: iso(-20), sourceRunId: 'run-ai-0031' }] : [];
const baselineObservations = (id) => id === PRIMARY_AI_ASSET_ID ? [
  { digestKind: 'AGENT_DEFINITION', comparisonOutcome: 'CHANGED', sourceRunId: 'run-ai-0042', observedAt: iso(-0.4), stale: false, changedFields: ['instruction', 'actionGroups[1].apiSchema'], observationVersion: '3' },
  { digestKind: 'PROMPT_TEMPLATE', comparisonOutcome: 'NO_BASELINE', sourceRunId: 'run-ai-0042', observedAt: iso(-0.4), stale: false, observationVersion: null },
] : [];
const baselineHistory = (id) => id === PRIMARY_AI_ASSET_ID ? [{ id: 'bh-1', digestKind: 'AGENT_DEFINITION', action: 'APPROVED', actor: 'fixture.analyst@example.test', sourceRunId: 'run-ai-0031', recordedAt: iso(-20) }, { id: 'bh-0', digestKind: 'AGENT_DEFINITION', action: 'REVOKED', actor: null, sourceRunId: null, recordedAt: iso(-34) }] : [];

// ── AI-BOM declared resources ───────────────────────────────────────────────
// [id, kind, name, version, identityKind, identityValue, deploymentState, linked, proposed]
const DECLARED = [
  [PRIMARY_DECLARED_RESOURCE_ID, 'MODEL', 'fixture-text-model-v2', '2.0.1', 'VERSIONED_IDENTIFIER', 'fixture-text-model-v2@2.0.1', 'LINKED', 'ai-model-claims-text', null],
  ['dr-claims-embeddings', 'MODEL', 'claims-embedding-model', '1.4', 'DIGEST', 'sha256:7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730', 'UNVERIFIED', null, null],
  ['dr-claims-training-set', 'DATASET', 'claims-history-2019-2025', null, 'SOURCE_SCOPED_REF', 's3://fixture-claims-datalake/curated/claims_history/partition=2019-2025/manifest.json', 'AMBIGUOUS', null, 'ai-kb-claims-docs'],
  ['dr-support-chat-model', 'MODEL', 'chat-deployment-eastus2', '2024-08-06', 'VERSIONED_IDENTIFIER', 'chat-deployment-eastus2@2024-08-06', 'LINKED', 'ai-model-azure-chat', null],
  ['dr-hr-handbook', 'DATASET', 'hr-handbook-corpus', '7', 'VERSIONED_IDENTIFIER', 'hr-handbook-corpus@7', 'UNVERIFIED', null, 'ai-search-hr-index'],
  ['dr-fraud-xgb', 'MODEL', 'fraud-scoring-xgboost', '0.9.3', 'DIGEST', 'sha256:4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a', 'UNVERIFIED', null, null],
  ['dr-redaction-ner', 'MODEL', 'pii-redaction-ner', null, 'SOURCE_SCOPED_REF', 'hf://fixture-org/pii-redaction-ner#main', 'AMBIGUOUS', null, null],
  ['dr-marketing-copy-set', 'DATASET', 'marketing-copy-approved', '2026.09', 'VERSIONED_IDENTIFIER', 'marketing-copy-approved@2026.09', 'LINKED', 'ai-kb-04', null],
  ['dr-ocr-model', 'MODEL', 'document-ocr-small', '3.1.0', 'DIGEST', 'sha256:e7f6c011776e8db7cd330b54174fd76f7d0216b612387a5ffcfb81e6f0919683', 'UNVERIFIED', null, null],
];
const declaredResources = DECLARED.map(([id, resourceKind, name, version, identityKind, identityValue, deploymentState, linkedArtifactId, proposedArtifactId], index) => ({
  id, sourceId: `bom-source-${(index % 3) + 1}`, bomId: `bom-${String(5 + (index % 3) * 9).padStart(4, '0')}`, bomComponentId: index === 6 ? null : `bomc-${id}`, resourceKind, name, version,
  identityKind, identityValue, deploymentState, linkedArtifactId, linkMethod: linkedArtifactId ? (index === 0 ? 'VERSIONED_IDENTIFIER_MATCH' : 'REVIEWED') : null,
  linkReviewedBy: linkedArtifactId && index !== 0 ? 'inventory.admin@example.test' : null, linkReviewedAt: linkedArtifactId && index !== 0 ? iso(-5) : null,
  proposedArtifactId, proposedBy: proposedArtifactId ? 'fixture.analyst@example.test' : null, proposedAt: proposedArtifactId ? iso(-1) : null,
  firstDeclaredAt: iso(-60 + index * 3), lastDeclaredAt: iso(-index * 0.9),
}));
const declaredById = new Map(declaredResources.map((resource) => [resource.id, resource]));

const setupActions = [
  { category: 'AMBIGUOUS_LINK', priority: 'HIGH', title: 'Resolve ambiguous deployment for claims-history-2019-2025', detail: 'Two knowledge bases match the declared S3 manifest; pick the deployed one.', evidenceId: 'dr-claims-training-set' },
  { category: 'UNVERIFIED_DECLARATION', priority: 'MEDIUM', title: 'Confirm claims-embedding-model is deployed', detail: 'No provider artifact matched the declared digest.', evidenceId: 'dr-claims-embeddings' },
  { category: 'PENDING_PROPOSAL', priority: 'MEDIUM', title: 'Review proposed mapping for hr-handbook-corpus', detail: 'An analyst proposed hr-handbook-index; an inventory admin must approve.', evidenceId: 'dr-hr-handbook' },
  { category: 'MISSING_COMPONENT', priority: 'LOW', title: 'pii-redaction-ner has no BOM component', detail: 'The declaration could not be tied to a component in the source BOM.', evidenceId: 'dr-redaction-ner' },
  { category: 'UNVERIFIED_DECLARATION', priority: 'LOW', title: 'Confirm document-ocr-small is deployed', detail: 'Declared in an AI-BOM revision older than 30 days.', evidenceId: 'dr-ocr-model' },
];

const correlationPath = (index, status) => ({
  id: `path-${status.toLowerCase()}-${index + 1}`, findingId: findingRecords[index].id, status, bomId: 'bom-0005', sourceRevision: 3 - (status === 'RETIRED' ? 1 : 0),
  components: [{ id: 'cmp-model', ref: 'model', name: 'fixture-text-model-v2', version: '2.0.1' }, { id: 'cmp-runtime', ref: 'runtime', name: 'inference-runtime', version: '1.8.0' }, { id: `cmp-lib-${index}`, ref: `lib-${index}`, name: findingRecords[index].packageName, version: findingRecords[index].packageVersion }],
  relationshipIds: [`rel-${index}-a`, `rel-${index}-b`], terminalComponentId: `comp-${index}`, matchMethod: index % 2 ? 'CPE_VERSION' : 'PURL_VERSION',
  confirmedAt: iso(-6 + index), retiredAt: status === 'RETIRED' ? iso(-2) : null, retirementReason: status === 'RETIRED' ? 'COMPONENT_REMOVED_IN_REVISION' : null, uncertain: index === 2,
  lifecycleHistory: index === 0 ? [{ status: 'ACTIVE', at: iso(-6), revision: 2 }, { status: 'ACTIVE', at: iso(-1), revision: 3 }] : undefined,
});
const correlation = (id, history, page) => {
  if (id !== PRIMARY_DECLARED_RESOURCE_ID) return { paths: [], gaps: [], pathCount: 0, gapCount: 0, page, size: 50 };
  const paths = history ? [correlationPath(3, 'RETIRED')] : [0, 1, 2].map((index) => correlationPath(index, 'ACTIVE'));
  return {
    paths, pathCount: paths.length, page, size: 50,
    gaps: history ? [] : [
      { id: 'gap-1', componentId: null, componentRef: 'tokenizer', reason: 'COMPONENT_UNRESOLVED', remediation: 'Add a purl or cpe for the tokenizer component in the AI-BOM.', sourceRevision: 3, detectedAt: iso(-1) },
      { id: 'gap-2', componentId: 'cmp-runtime', componentRef: 'runtime', reason: 'NO_INVENTORY_MATCH', remediation: 'Ingest the inference runtime image SBOM.', sourceRevision: 3, detectedAt: iso(-1) },
    ],
    gapCount: history ? 0 : 2, associationCount: history ? 1 : 4,
    associationsWithoutPaths: history ? [] : [{ id: 'assoc-legacy-1', findingId: findingRecords[4].id, status: 'ACTIVE', confirmedAt: null, retiredAt: null, retirementReason: null, lifecycleHistory: [] }],
  };
};

const declaredDetail = (resource, index) => ({
  correlation: correlation(resource.id, false, 0), resource, sourceBomType: 'AIBOM', sourceState: index === 5 ? 'HELD_ENTITLEMENT' : 'ACTIVE', sourceRevision: 3 - (index % 3),
  currentInLatestRevision: index !== 8,
  component: resource.bomComponentId ? { componentId: resource.bomComponentId, name: resource.name, version: resource.version, purl: resource.identityKind === 'VERSIONED_IDENTIFIER' ? `pkg:huggingface/fixture-org/${resource.name}@${resource.version}` : null, license: index % 2 ? null : 'Apache-2.0', scope: index % 3 ? null : 'required', componentType: resource.resourceKind === 'MODEL' ? 'machine-learning-model' : 'data' } : null,
  completeness: index === 6 ? null : { completeness: index % 2 ? 'COMPLETE_ASSET_SOFTWARE' : 'PARTIAL', assertedBy: index % 3 ? null : 'ml-platform@example.test', assertedAt: iso(-7) },
  projection: { provenanceProjected: index !== 4, provenanceProjectedAt: index !== 4 ? iso(-3) : null, bomFormat: 'CycloneDX', specVersion: '1.6', latestReceiptOperation: index !== 4 ? 'PROVENANCE_PROJECTION' : null, latestReceiptCompletedAt: index !== 4 ? iso(-3) : null },
});

// ── Router ──────────────────────────────────────────────────────────────────
const AI_ID = /^\/ai-security\/artifacts\/([^/]+)(\/.*)?$/;

/** Returns { status, json } for an Inventory/lifecycle request, or undefined when outside the family. */
export function inventoryFixtureFor(rawUrl, method = 'GET') {
  const url = new URL(rawUrl);
  const path = url.pathname.replace(/^\/api/, '');
  const params = url.searchParams;
  const ok = (json) => ({ status: 200, json });
  const notFound = { status: 404, json: { message: 'Not found (fixture)' } };
  const segment = (index) => decodeURIComponent(path.split('/')[index] ?? '');

  if (path === '/assets') return ok(assets);
  if (path.startsWith('/assets/hosts/')) {
    const detail = hostDetails().find((candidate) => candidate.host.assetId === segment(3));
    return detail ? ok(hostDetailBody(detail)) : notFound;
  }
  if (path === '/dashboard') return ok(dashboardBody());
  if (path === '/dashboard/applicable-software') return ok(itemPage(applicableSoftware(), params, 100));
  if (path === '/eol/status/summary') return ok(eolSummary());
  if (path === '/eol/mappings/unresolved') {
    return ok(springPage(identities.filter((identity) => identity.needsEolMapping).map((identity) => ({
      softwareIdentityId: identity.id, vendor: identity.vendor ?? '', product: identity.product, displayName: identity.displayName, normalizedKey: identity.normalizedKey,
      assetCount: identity.assetCount, componentCount: identity.componentCount, versionCount: identity.versionCount, openFindingCount: identity.openFindingCount,
      openVulnerabilityCount: identity.openVulnerabilityCount, lastObservedAt: identity.lastObservedAt,
    })), params));
  }
  if (path === '/operations/quality/summary') return ok(qualitySummary);
  if (path === '/upgrade-recommendation' && method === 'POST') {
    return ok({ recommendedVersion: '2.24.1', upgradeNotes: 'Synthetic recommendation: move to the latest supported minor release and redeploy dependent services.', urgency: 'HIGH' });
  }
  if (path === '/inventory/components') return ok(itemPage(narrowComponents(params).map(stripInternal), params));
  if (path === '/inventory/components/filters') {
    return ok({ assetTypes: ['HOST', 'CONTAINER_IMAGE', 'APPLICATION'], componentStatuses: ['ACTIVE', 'RETIRED'],
      sourceSystems: [...new Set(components.map((component) => component.sourceSystem))], ecosystems: [...new Set(components.map((component) => component.ecosystem))] });
  }
  if (path === '/inventory/software-identities') return ok(springPage(narrowIdentities(params).map(summaryOf), params));
  if (path === '/inventory/software-identities/funnel') {
    return ok({ recordsFound: components.length, uniqueSoftware: identities.length, softwareWithVulnerabilities: identities.filter((identity) => identity.openVulnerabilityCount).length,
      softwareWithFindings: identities.filter((identity) => identity.openFindingCount).length, sourceCount: new Set(components.map((component) => component.sourceSystem)).size, updatedAt: iso(-0.2) });
  }
  const identityMatch = path.match(/^\/inventory\/software-identities\/([^/]+)(\/metadata)?$/);
  if (identityMatch) {
    const identity = identityById.get(decodeURIComponent(identityMatch[1]));
    if (!identity) return notFound;
    if (!identityMatch[2]) return ok(identityDetail(identity));
    const saved = { softwareIdentityId: identity.id, owner: identity.id === PRIMARY_SOFTWARE_IDENTITY_ID ? 'Core Infrastructure' : '', licensed: 'Yes', licenseType: 'Apache-2.0', supportGroup: identity.id === PRIMARY_SOFTWARE_IDENTITY_ID ? 'Platform Engineering' : '', recommendation: identity.id === PRIMARY_SOFTWARE_IDENTITY_ID ? 'Upgrade to 2.17.2 or later across all deployments.' : '', recommendationUpdatedAt: iso(-3), updatedAt: iso(-3) };
    return ok(method === 'PUT' ? { ...saved, updatedAt: iso(0) } : saved);
  }

  if (path === '/bom/application-risk') return ok(applicationRisk());
  if (path === '/bom/components') {
    const size = Number(params.get('size') ?? 2000);
    const page = Number(params.get('page') ?? 0);
    return ok(bomComponents().slice(page * size, page * size + size));
  }
  if (path.startsWith('/bom/components/')) {
    const summary = bomComponents().find((component) => component.componentId === segment(3));
    return summary ? ok(bomComponentDetail(summary)) : notFound;
  }
  if (/^\/bom\/assets\/[^/]+\/cves$/.test(path)) {
    return ok(components.filter((component) => component.assetId === segment(3)).flatMap((component) => component.cveIds.map((cveId, index) => ({
      vulnerabilityId: `vuln-${cveId}`, componentId: component.id, externalId: cveId, ...CVE_META(cveId, index), packageName: component.packageName, version: component.version ?? null, lastEvaluatedAt: iso(-index * 0.3),
    }))));
  }
  if (path === '/bom/inventory') {
    const size = Number(params.get('size') ?? 50);
    const page = Number(params.get('page') ?? 0);
    return ok(bomInventory.slice(page * size, page * size + size));
  }
  if (path === '/bom/dashboard') return ok(bomDashboard());
  if (path === '/bom/sources') return ok([]);
  if (path === '/bom/support') return ok({ entries: [{ specFamily: 'CYCLONEDX', documentFormat: 'JSON', version: '1.6', supportLevel: 'FULL', supported: true, notes: '' }, { specFamily: 'SPDX', documentFormat: 'JSON', version: '2.3', supportLevel: 'PARTIAL', supported: true, notes: 'Relationships beyond DEPENDS_ON are ignored.' }] });
  const bomMatch = path.match(/^\/bom\/inventory\/([^/]+)(\/lineage)?$/);
  if (bomMatch) {
    const item = bomInventory.find((candidate) => candidate.id === decodeURIComponent(bomMatch[1]));
    if (!item) return notFound;
    if (method === 'DELETE') return { status: 204, body: '' };
    return ok(bomMatch[2] ? bomLineage(item) : bomDetail(item));
  }

  if (path === '/bom/declared-resources') {
    const state = params.get('deploymentState');
    return ok(declaredResources.filter((resource) => !state || resource.deploymentState === state));
  }
  if (path === '/bom/declared-resources/setup-actions') return ok(setupActions);
  const declaredMatch = path.match(/^\/bom\/declared-resources\/([^/]+)(\/.*)?$/);
  if (declaredMatch) {
    const resource = declaredById.get(decodeURIComponent(declaredMatch[1]));
    if (!resource) return notFound;
    const rest = declaredMatch[2] ?? '';
    if (rest === '') return ok(declaredDetail(resource, declaredResources.indexOf(resource)));
    if (rest === '/findings') return ok(resource.id === PRIMARY_DECLARED_RESOURCE_ID ? findingRecords.slice(0, 4) : []);
    if (rest === '/correlation') return ok(correlation(resource.id, params.get('history') === 'true', Number(params.get('page') ?? 0)));
    if (rest === '/mapping/propose') return ok({ ...resource, proposedArtifactId: 'ai-model-claims-text', proposedBy: 'fixture-analyst', proposedAt: iso(0) });
    if (rest === '/mapping/approve') return ok({ ...resource, deploymentState: 'LINKED', linkedArtifactId: resource.proposedArtifactId, linkMethod: 'REVIEWED', linkReviewedBy: 'fixture-analyst', linkReviewedAt: iso(0), proposedArtifactId: null });
    if (rest === '/mapping/remove') return ok({ ...resource, deploymentState: 'UNVERIFIED', linkedArtifactId: null, linkMethod: null, proposedArtifactId: null });
    return ok({});
  }

  if (path === '/ai-security/runs') return ok(aiRuns);
  if (path === '/ai-security/summary') return ok(aiSummary());
  if (path === '/ai-coverage') return ok(aiCoverage);
  if (path === '/ai-security/top-risk-artifacts') return ok(topRisk(Number(params.get('limit') ?? 5)));
  if (path === '/ai-security/severity-grid') return ok(severityGrid());
  if (path === '/ai-security/artifact-summaries') return ok(aiPage(narrowAiSummaries(params).map((entry) => entry.summary), params));
  if (path === '/ai-security/artifacts') return ok(aiPage(narrowAiSummaries(params).map((entry) => entry.artifact), params));
  if (path === '/ai-security/inventory/knowledge-data') return ok(aiInventoryList('knowledge-data', params));
  if (path === '/ai-security/inventory/mcp') return ok(aiInventoryList('mcp', params));
  if (path === '/ai-security/graph') {
    const root = params.get('rootArtifactId');
    if (!root) return ok({ nodes: aiArtifacts.slice(0, 22).map((entry) => entry.artifact), edges: AI_EDGES, truncated: false });
    return aiById.has(root) ? ok(aiGraph(root, Number(params.get('depth') ?? 2))) : undefined;
  }
  const aiMatch = path.match(AI_ID);
  if (aiMatch && aiById.has(decodeURIComponent(aiMatch[1]))) {
    const id = decodeURIComponent(aiMatch[1]);
    const rest = aiMatch[2] ?? '';
    if (rest === '') return ok(aiById.get(id).artifact);
    if (rest === '/versions') return ok(aiPage(agentVersions(id), params));
    if (rest === '/digest-baselines') return ok(baselines(id));
    if (rest === '/digest-baselines/observations') return ok(baselineObservations(id));
    if (rest === '/digest-baselines/history') return ok(baselineHistory(id));
    if (rest === '/activity-evidence') return ok([]);
    return ok(baselines(id)[0] ?? {});
  }
  const postureMatch = path.match(/^\/ai-assets\/([^/]+)\/posture$/);
  if (postureMatch && aiById.has(decodeURIComponent(postureMatch[1]))) return ok(posture(decodeURIComponent(postureMatch[1])));
  const ownerMatch = path.match(/^\/ai-artifacts\/([^/]+)\/owner$/);
  if (ownerMatch && aiById.has(decodeURIComponent(ownerMatch[1]))) {
    return ok({ artifactId: decodeURIComponent(ownerMatch[1]), ownerName: 'Claims Engineering', ownerState: 'CONFIRMED', updatedAt: iso(0) });
  }
  return undefined;
}
