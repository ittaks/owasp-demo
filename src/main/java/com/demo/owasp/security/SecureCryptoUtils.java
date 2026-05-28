package com.demo.owasp.security;

import org.springframework.stereotype.Component;
import java.security.SecureRandom;
import java.util.Base64;

@Component
public class SecureCryptoUtils {

    // OWASP A04 COMPLIANCE: Korištenje CSPRNG (Cryptographically Secure Pseudo-Random Number Generator).
    // Za razliku od standardne klase Random, SecureRandom pruža visoku entropiju i nepredvidljivost (CWE-338).
    // Moderni Java API automatski povlači sigurnu sjemenku (seed) iz operacijskog sustava (/dev/urandom na Linuxu),
    // tako da programer NE smije ručno postavljati predvidljive fiksne seed-ove (CWE-335, CWE-337).
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Generira siguran, nepredvidiv token visoke entropije (npr. za privremene transakcijske kodove, MFA ili tokene).
     * Rješava: CWE-330 (Nedovoljno nasumične vrijednosti) i CWE-334 (Mali prostor nasumičnih vrijednosti).
     */
    public String generateSecureToken(int byteLength) {
        byte[] randomBytes = new byte[byteLength];
        secureRandom.nextBytes(randomBytes); // Popunjavanje visokom entropijom
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
}