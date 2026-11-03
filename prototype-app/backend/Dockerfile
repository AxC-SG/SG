FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /workspace
COPY pom.xml .
RUN mvn -q -DskipTests dependency:go-offline
COPY src ./src
RUN mvn -q -DskipTests package

FROM eclipse-temurin:17-jre-jammy
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends busybox-static postgresql-client \
    && rm -rf /var/lib/apt/lists/* \
    && addgroup --system vulnwatch \
    && adduser --system --ingroup vulnwatch vulnwatch
COPY --from=build /workspace/target/vulnwatch-backend-*.jar /app/vulnwatch-backend.jar
COPY scripts /app/scripts
RUN chmod 500 /app/scripts/run-render-migration.sh \
    && chmod 400 /app/scripts/provision-runtime-role.sql \
    && chown -R vulnwatch:vulnwatch /app/scripts
USER vulnwatch:vulnwatch
EXPOSE 8080
ENV JAVA_TOOL_OPTIONS=""
ENV JAVA_OPTS="-XX:MaxRAMPercentage=60.0 -XX:InitialRAMPercentage=10.0 -XX:MaxMetaspaceSize=192m -XX:+ExitOnOutOfMemoryError"
CMD ["sh", "-c", "if [ \"${APP_RUNTIME_ROLE:-all}\" = \"schema-migrator\" ]; then exec /app/scripts/run-render-migration.sh; else exec java $JAVA_TOOL_OPTIONS $JAVA_OPTS -jar /app/vulnwatch-backend.jar; fi"]
