FROM eclipse-temurin:21-jdk
COPY target/owasp-demo.jar app.jar
ENTRYPOINT ["java","-jar","/app.jar"]