# Prikaz 5.B: Refaktorirani, očvrsnuti Dockerfile (Smanjena površina napada i ne-root korisnik)
FROM eclipse-temurin:21-jre-alpine
RUN apk upgrade --no-cache
# OWASP A03: Kreiranje namjenskog ne-root korisnika radi primjene načela najmanjih privilegija
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

// Prebacivanje u kontekst ograničenog korisnika
USER appuser

# Kopiranje artefakta uz eksplicitnu dodjelu vlasništva kreiranom korisniku
COPY --chown=appuser:appgroup target/owasp-demo.jar app.jar

ENTRYPOINT ["java","-jar","/app.jar"]