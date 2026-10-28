FROM maven:3.9.9-eclipse-temurin-17@sha256:f58d59b6273e785ac0a4477f6e9b5ba1d7731c75b906c0f7b34076f1851318cc AS build
WORKDIR /workspace
COPY pom.xml .
RUN mvn -q -DskipTests dependency:go-offline
COPY src ./src
RUN mvn -q -DskipTests package

FROM eclipse-temurin:24-jre-noble@sha256:b416d02335e702b0403ff280de9475a3348e29382285969c9d4e17862ce632e7
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
