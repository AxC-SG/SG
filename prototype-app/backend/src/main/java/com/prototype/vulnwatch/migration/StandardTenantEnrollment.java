package com.prototype.vulnwatch.migration;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Set;
import java.util.UUID;

/** Standard reservations are the customer registry rows and their UUID-derived schemas. */
final class StandardTenantEnrollment {

    private StandardTenantEnrollment() {
    }

    record Request(UUID id, String slug, String name) {
        static Request parse(String[] args) {
            if (args.length == 0) {
                return null;
            }
            if (args.length != 4 || !"--provision-standard".equals(args[0])
                    || !args[1].matches("[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")) {
                throw new IllegalArgumentException("Expected --provision-standard <uuid> <slug> <name>");
            }
            String slug = args[2];
            String name = args[3].strip();
            if (!slug.matches("[a-z0-9]+(?:-[a-z0-9]+)*") || slug.length() > 120
                    || Set.of("default-workspace", "sg-internal").contains(slug)
                    || name.isEmpty() || name.length() > 255 || "SG Internal".equalsIgnoreCase(name)
                    || name.chars().anyMatch(Character::isISOControl)) {
                throw new IllegalArgumentException("Invalid Standard customer slug or name");
            }
            return new Request(UUID.fromString(args[1]), slug, name);
        }

        String schema() {
            return "tenant_" + id.toString().replace("-", "");
        }
    }

    // Called under the same advisory lock as reservation and activation.
    static void configure(Connection connection, int requestedLimit) throws SQLException {
        connection.setAutoCommit(false);
        try {
            int currentLimit = limit(connection);
            if (currentLimit == 0 && requestedLimit != 0) {
                try (var statement = connection.createStatement()) {
                    statement.execute("lock table platform.tenants in share row exclusive mode");
                }
                if (customerCount(connection) != 0) {
                    throw new IllegalStateException("Standard enrollment requires a fresh customer registry");
                }
                try (var statement = connection.prepareStatement("""
                        insert into platform.standard_enrollment_policy (customer_limit) values (?)
                        """)) {
                    statement.setInt(1, requestedLimit);
                    statement.executeUpdate();
                }
            } else if (currentLimit != requestedLimit) {
                throw new IllegalStateException("Configured Standard enrollment limit differs from the recorded limit");
            }
            connection.commit();
        } catch (Exception ex) {
            connection.rollback();
            throw ex;
        } finally {
            connection.setAutoCommit(true);
        }
    }

    static void requireCapacityPolicy(Connection connection, int configuredLimit) throws SQLException {
        int recordedLimit = limit(connection);
        if (recordedLimit == 0 || recordedLimit != configuredLimit) {
            throw new IllegalStateException("Run the matching Standard bootstrap before provisioning customers");
        }
        if (customerCount(connection) > recordedLimit) {
            throw new IllegalStateException("Standard customer enrollment exceeds the recorded limit");
        }
    }

    static String reserve(Connection connection, Request request, int limit) throws SQLException {
        connection.setAutoCommit(false);
        try {
            String status = existingStatus(connection, request);
            if (status == null) {
                if (customerCount(connection) >= limit) {
                    throw new IllegalStateException("Standard customer enrollment limit reached");
                }
                // Commit the schema and its ownership record together. A pre-existing schema
                // without this reservation causes CREATE to fail and is never reused.
                try (var statement = connection.createStatement()) {
                    statement.execute("create schema " + request.schema());
                }
                try (var statement = connection.prepareStatement("""
                        insert into platform.tenants
                            (id, slug, name, schema_name, classification, status, plan_code, created_at, updated_at,
                             max_connector_count, max_service_account_count, max_daily_sbom_uploads,
                             max_export_rows, max_daily_exposure_refreshes)
                        values (?, ?, ?, ?, 'CUSTOMER', 'PROVISIONING', 'PRO', now(), now(), 10, 25, 100, 50000, 25)
                        """)) {
                    statement.setObject(1, request.id());
                    statement.setString(2, request.slug());
                    statement.setString(3, request.name());
                    statement.setString(4, request.schema());
                    statement.executeUpdate();
                }
                status = "PROVISIONING";
            }
            connection.commit();
            return status;
        } catch (Exception ex) {
            connection.rollback();
            throw ex;
        } finally {
            connection.setAutoCommit(true);
        }
    }

    private static String existingStatus(Connection connection, Request request) throws SQLException {
        try (var statement = connection.prepareStatement("""
                select slug, name, schema_name, status, classification, deleted_at
                from platform.tenants where id = ?
                """)) {
            statement.setObject(1, request.id());
            try (var row = statement.executeQuery()) {
                if (!row.next()) {
                    return null;
                }
                String status = row.getString("status");
                if (!"CUSTOMER".equals(row.getString("classification")) || row.getObject("deleted_at") != null
                        || !request.slug().equals(row.getString("slug")) || !request.name().equals(row.getString("name"))
                        || !request.schema().equals(row.getString("schema_name"))
                        || !Set.of("PROVISIONING", "PROVISIONING_FAILED", "ACTIVE").contains(status)) {
                    throw new IllegalStateException("Standard enrollment request conflicts with an existing tenant");
                }
                return status;
            }
        }
    }

    private static int limit(Connection connection) throws SQLException {
        try (var statement = connection.createStatement();
             var row = statement.executeQuery("select customer_limit from platform.standard_enrollment_policy")) {
            return row.next() ? row.getInt(1) : 0;
        }
    }

    private static int customerCount(Connection connection) throws SQLException {
        // Failed and suspended workspaces retain their allocation until separately retired.
        try (var statement = connection.createStatement();
             var row = statement.executeQuery("select count(*) from platform.tenants where classification = 'CUSTOMER'")) {
            row.next();
            return row.getInt(1);
        }
    }
}
