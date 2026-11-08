FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /workspace
COPY pom.xml .
RUN mvn -q -DskipTests dependency:go-offline
COPY src ./src
RUN mvn -q -DskipTests package

FROM eclipse-temurin:17-jre-jammy AS runtime
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends busybox-static postgresql-client \
    && rm -rf /var/lib/apt/lists/* \
    && addgroup --system vulnwatch \
    && adduser --system --ingroup vulnwatch vulnwatch
COPY --from=build /workspace/target/vulnwatch-backend-*.jar /app/vulnwatch-backend.jar
COPY scripts /app/scripts
RUN chmod 500 /app/scripts/run-schema-migration.sh /app/scripts/run-render-migration.sh \
    && chmod 400 /app/scripts/provision-runtime-role.sql \
    && chown -R vulnwatch:vulnwatch /app/scripts
USER vulnwatch:vulnwatch
EXPOSE 8080
ENV JAVA_TOOL_OPTIONS=""
ENV JAVA_OPTS="-XX:MaxRAMPercentage=60.0 -XX:InitialRAMPercentage=10.0 -XX:MaxMetaspaceSize=192m -XX:+ExitOnOutOfMemoryError"
CMD ["sh", "-c", "if [ \"${APP_RUNTIME_ROLE:-all}\" = \"schema-migrator\" ]; then exec /app/scripts/run-schema-migration.sh --run-once; else exec java $JAVA_TOOL_OPTIONS $JAVA_OPTS -jar /app/vulnwatch-backend.jar; fi"]

# Build this target for ECS. Review the RDS roots before updating either regional pin.
FROM runtime AS aws-runtime
ADD --checksum=sha256:b1711d12bae51838581281e23b6cb97b1074016873b4dafc80ed14002462dd77 --chmod=0444 https://truststore.pki.rds.amazonaws.com/us-east-1/us-east-1-bundle.pem /app/rds-ca.pem
ADD --checksum=sha256:d73890748b5a95551800df8a6f07c9c800e32ed34da7e6c9505918bf8ac2398b --chmod=0444 https://truststore.pki.rds.amazonaws.com/ap-southeast-2/ap-southeast-2-bundle.pem /app/rds-ca-ap-southeast-2.pem

FROM runtime AS default-runtime
CMD ["sh", "-c", "if [ \"${APP_RUNTIME_ROLE:-all}\" = \"schema-migrator\" ]; then exec /app/scripts/run-render-migration.sh; else exec java $JAVA_TOOL_OPTIONS $JAVA_OPTS -jar /app/vulnwatch-backend.jar; fi"]
