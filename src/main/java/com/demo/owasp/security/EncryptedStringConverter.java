package com.demo.owasp.security;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

@Converter
@Component
public class EncryptedStringConverter implements AttributeConverter<String, String> {

    // OWASP A04 MITIGATION: Koristimo isključivo "AES/GCM/NoPadding" (Authenticated Encryption).
    // Strogo izbjegavamo stare modove poput ECB (koji ne skriva uzorke) ili CBC koji je ranjiv na
    // Padding Oracle napade i zahtijeva kompleksne padding sheme (CWE-327, CWE-1240).
    private static final String ALGORITHM = "AES/GCM/NoPadding";

    // Standardna preporučena duljina za GCM Inicijalizacijski Vektor (IV) je 12 bajtova (96 bita)
    private static final int GCM_IV_LENGTH = 12;

    // Duljina autentifikacijskog taga (128 bita) koji jamči integritet i autentičnost podataka
    private static final int GCM_TAG_LENGTH = 128;

    private final byte[] secretKeyBytes;

    // OWASP A04 PRNG FIX: Eksplicitno koristimo SecureRandom (CSPRNG) koji povlači entropiju
    // iz operacijskog sustava, čime sprječavamo predvidljivost IV-a (CWE-338, CWE-331).
    private final SecureRandom secureRandom = new SecureRandom();

    // OWASP A04 & A02: Kriptografski ključ se ubrizgava iz vanjske konfiguracije (okruženja),
    // čime sprječavamo postojanje hardkodiranih ključeva unutar izvornog koda (CWE-321).
    public EncryptedStringConverter(@Value("${app.crypto.secret-key}") String secretKey) {
        // Za AES-256 snagu enkripcije, ključ u varijabli okruženja mora biti točno 32 bajta (CWE-326).
        this.secretKeyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public String convertToDatabaseColumn(String attribute) {
        if (attribute == null || attribute.isEmpty()) {
            return null;
        }
        try {
            // OWASP A04 IV REUSE MITIGATION: Generiramo potpuno novi, kriptografski siguran IV
            // za SVAKU pojedinačnu operaciju zapisivanja u bazu. Isti IV se nikada ne smije
            // upotrijebiti dvaput s istim ključem (CWE-323, CWE-329).
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            SecretKeySpec keySpec = new SecretKeySpec(secretKeyBytes, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, parameterSpec);

            byte[] ciphertext = cipher.doFinal(attribute.getBytes(StandardCharsets.UTF_8));

            // Spajamo IV i ciphertext u zajednički niz kako bismo mogli rekonstruirati parametre pri dekripciji
            byte[] combined = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);

            // Spremanje u bazu kao siguran Base64 tekst
            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            // Sprječavamo curenje internih kriptografskih detalja kroz općenitu iznimku
            throw new RuntimeException("Kritični neuspjeh prilikom šifriranja podataka u mirovanju.", e);
        }
    }

    @Override
    public String convertToEntityAttribute(String dbData) {
        if (dbData == null || dbData.isEmpty()) {
            return null;
        }
        try {
            byte[] combined = Base64.getDecoder().decode(dbData);

            // Izdvajanje IV-a iz prvih 12 bajtova podataka
            byte[] iv = new byte[GCM_IV_LENGTH];
            System.arraycopy(combined, 0, iv, 0, iv.length);

            // Izdvajanje čistog kriptograma
            int ciphertextLength = combined.length - GCM_IV_LENGTH;
            byte[] ciphertext = new byte[ciphertextLength];
            System.arraycopy(combined, GCM_IV_LENGTH, ciphertext, 0, ciphertextLength);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            SecretKeySpec keySpec = new SecretKeySpec(secretKeyBytes, "AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, parameterSpec);

            // OWASP A04 INTEGRITY CHECK: Budući da je u pitanju GCM (Authenticated Encryption),
            // metoda doFinal() će automatski potvrditi MAC autentifikacijski tag. Ako je netko izvan aplikacije
            // ručno mijenjao bitove u bazi, verifikacija će pasti i spriječiti ubacivanje malicioznog sadržaja (CWE-347).
            byte[] decryptedBytes = cipher.doFinal(ciphertext);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Kritični neuspjeh dekripcije. Podaci su možda modificirani ili kompromitirani.", e);
        }
    }
}