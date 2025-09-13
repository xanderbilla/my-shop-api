# Use Eclipse Temurin 21 as the base image (more secure)
FROM eclipse-temurin:21-jdk-alpine

# Set working directory
WORKDIR /app

# Copy Maven wrapper and pom.xml
COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .

# Make Maven wrapper executable
RUN chmod +x ./mvnw

# Copy source code
COPY src ./src

# Build the application
RUN ./mvnw clean package -DskipTests

# Expose port
EXPOSE 8761

# Run the application
CMD ["java", "-jar", "target/service-registry-0.0.1-SNAPSHOT.jar"]
