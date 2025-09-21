FROM openjdk:21-jdk-slim

WORKDIR /app

COPY target/carousel-0.0.1-SNAPSHOT.jar carousel-service.jar

EXPOSE 8085

ENTRYPOINT ["java", "-jar", "carousel-service.jar"]