# -------------------------
# Stage 1: build with Gradle
# -------------------------
FROM gradle:8-jdk21 AS builder
WORKDIR /home/gradle/project

# copy Gradle wrapper + build files first for layer caching
COPY --chown=gradle:gradle gradlew .
COPY --chown=gradle:gradle gradle gradle
COPY --chown=gradle:gradle settings.gradle build.gradle ./

# copy source
COPY --chown=gradle:gradle src ./src

# make wrapper executable and build fat jar (skip tests for faster local builds)
RUN chmod +x ./gradlew && ./gradlew clean bootJar --no-daemon -x test --console=plain

# -------------------------
# Stage 2: runtime image
# -------------------------
FROM eclipse-temurin:21-jre AS runtime

# create non-root user for security
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

WORKDIR /app

# copy jar from builder stage
COPY --from=builder /home/gradle/project/build/libs/*.jar app.jar

# create mount points for keystore, public certs and CA private keys
RUN mkdir -p /etc/certs /etc/certs_pub /etc/pki/private \
    && chown -R appuser:appgroup /etc/certs /etc/certs_pub /etc/pki/private || true
# run as non-root
USER appuser

EXPOSE 8443

ENTRYPOINT ["java", "-jar", "/app/app.jar"]