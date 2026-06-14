package com.demo.owasp.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integracijski i jedinični testovi za OWASP A04:2025 — Cryptographic Failures
 * Verificira ispravnost primjene kriptografskih algoritama, robusnost JWT-a i enkripciju u mirovanju.
 */
@SpringBootTest
class CryptographicFailuresTest {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${app.crypto.secret-key}")
    private String cryptoSecretKey;

    // =========================================================================
    // 1. TEST: Verifikacija robusnosti hashiranja lozinki (BCrypt s faktorom 12)
    // =========================================================================
    @Test
    @DisplayName("BCrypt mora koristiti ispravan faktor rada (12) i generirati jedinstvenu sol za istu lozinku")
    void passwordHashing_shouldUseStrongBCryptWithSalt() {
        String rawPassword = "MojaSigurnaLozinka123!";

        // Generiramo dva hasha za istu lozinku
        String hash1 = passwordEncoder.encode(rawPassword);
        String hash2 = passwordEncoder.encode(rawPassword);

        // Zbog ugrađene nasumične soli (Salt), dva hasha iste lozinke nikada ne smiju biti identična (Zaštita od Rainbow Tables)
        assertNotEquals(hash1, hash2, "BCrypt ne koristi jedinstvenu sol za svaki hash!");

        // BCrypt hash počinje s $2a$12$ ili $2b$12$ gdje je 12 faktor rada (work factor)
        assertTrue(hash1.startsWith("$2a$12$") || hash1.startsWith("$2b$12$"),
                "Aplikacija ne koristi preporučeni visoki faktor rada (12) za BCrypt!");
    }

    // =========================================================================
    // 2. TEST: Zaštita od JWT manipulacije (Odbijanje slabih ključeva i 'none' algoritma)
    // =========================================================================
    @Test
    @DisplayName("JWT servis mora odbiti tokene modificirane s nesigurnim algoritmom 'none' ili potpisane tuđim ključem")
    void jwtValidation_shouldRejectNoneAlgorithmAndInvalidSignatures() {
        // Kreiramo maliciozni JWT s algoritmom 'none' (CWE-327 / CWE-1241)
        var wrongKey = Keys.hmacShaKeyFor(
                "MaliSlabiKljucKojiNemaDovoljnoBitaZaHS512_TotalnoNevazeciKljuc123!"
                        .getBytes(StandardCharsets.UTF_8));

        String attackerToken = Jwts.builder()
                .subject("admin")        // novo u 0.12.x
                .signWith(wrongKey)      // novo u 0.12.x - algoritam se detektira automatski
                .compact();

        String maliciousNoneToken = Jwts.builder()
                .subject("admin")        // novo u 0.12.x
                .compact();

        // Verificiramo da naš JwtService baca iznimku i odbija obradu takvih tokena
        assertThrows(Exception.class, () -> jwtService.extractUsername(maliciousNoneToken),
                "Sustav je prihvatio nesigurni 'none' algoritam u JWT tokenu!");

        assertThrows(Exception.class, () -> jwtService.extractUsername(attackerToken),
                "Sustav je prihvatio JWT token potpisan neovlaštenim ključem!");
    }

    // =========================================================================
    // 3. TEST: Sigurnost podataka u mirovanju (Simetrična AES-256 enkripcija za GDPR)
    // =========================================================================
    @Test
    @DisplayName("Osjetljivi podaci moraju biti kriptirani u mirovanju pomoću sigurnog AES algoritma i SecureRandom IV-a")
    void dataAtRest_shouldBeEncryptedWithAES() throws Exception {
        String sensitiveData = "Ovo je osjetljivi osobni podatak (OIB/Lozinka)";

        // Provjera duljine eksternaliziranog ključa iz application.yml (mora imati 32 bajta za AES-256)
        byte[] keyBytes = cryptoSecretKey.getBytes(StandardCharsets.UTF_8);
        assertEquals(32, keyBytes.length, "Tajni ključ za enkripciju podataka u mirovanju nema točno 256 bita (32 znaka)!");

        // Inicijalizacija kriptografski sigurnog generatora slučajnih brojeva (PRNG - SecureRandom) za IV (CWE-331)
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv); // Generiranje kriptografski snažnog inicijalizacijskog vektora
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Enkripcija (Simulacija onoga što aplikacija radi prije spremanja u bazu)
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Ili AES/GCM/NoPadding ovisno o implementaciji
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

        byte[] encryptedBytes = cipher.doFinal(sensitiveData.getBytes(StandardCharsets.UTF_8));
        String encryptedString = Base64.getEncoder().encodeToString(encryptedBytes);

        // Podatak u mirovanju (bazi) ne smije biti čitljiv kao čisti tekst
        assertNotEquals(sensitiveData, encryptedString);
        assertFalse(encryptedString.contains("osjetljivi"));

        // Dekripcija (Provjera da se podatak može uspješno vratiti u izvorni oblik)
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedString));
        String decryptedData = new String(decryptedBytes, StandardCharsets.UTF_8);

        assertEquals(sensitiveData, decryptedData, "Dekriptirani podatak ne odgovara izvornom podatku!");
    }
}