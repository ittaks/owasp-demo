# Prikaz 5.B: Refaktorirani, očvrsnuti Dockerfile (Smanjena površina napada i ne-root korisnik)
FROM eclipse-temurin:21-jre-alpine
RUN apk upgrade --no-cache
# OWASP A03: Kreiranje namjenskog ne-root korisnika radi primjene načela najmanjih privilegija
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

USER appuser

# Kopiranje artefakta uz eksplicitnu dodjelu vlasništva kreiranom korisniku
COPY --chown=appuser:appgroup target/owasp-demo-0.0.1-SNAPSHOT.jar app.jar

ENTRYPOINT ["java","-jar","/app.jar"]