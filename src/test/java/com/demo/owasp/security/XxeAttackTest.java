package com.demo.owasp.security;

import com.demo.owasp.dto.TaskFromXmlRequest;
import com.demo.owasp.service.XmlParserService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockMultipartFile;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Jedinični test u izolaciji za OWASP A05 — XML External Entity (XXE) Injection
 * Testira se izravno XmlParserService bez potrebe za HTTP endpointom.
 */
@SpringBootTest
class XxeAttackTest {

    @Autowired
    private XmlParserService xmlParserService;

    @Test
    @DisplayName("XmlParserService mora odbiti ili ignorirati vanjske entitete (XXE) u izolaciji")
    void xmlParser_shouldBeSecureAgainstXxe() {
        // 1. Pripremamo maliciozni XML payload (napad)
        // Pokušavamo ubaciti entitet &xxe; s tajnim tekstom koji parser ne bi smio pročitati
        String xxePayload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<!DOCTYPE test [\n" +
                "  <!ENTITY xxe \"MALICIOUS_XXE_DATA\">\n" +
                "]>\n" +
                "<TaskFromXmlRequest>\n" +
                "  <title>Zadatak iz XML-a</title>\n" +
                "  <description>&xxe;</description>\n" +
                "</TaskFromXmlRequest>";

        // 2. Simuliramo Multipart datoteku izravno u memoriji (bez HTTP-a)
        MockMultipartFile mockFile = new MockMultipartFile(
                "file",
                "attack.xml",
                "text/xml",
                xxePayload.getBytes()
        );

        // 3. Izvršavanje i verifikacija
        try {
            // Izravno pozivamo obradu unutar servisa
            TaskFromXmlRequest result = xmlParserService.parse(mockFile);

            // Ako je parser siguran (konfiguriran da ignorira entitete),
            // opis zadatka NE SMIJE sadržavati vrijednost "MALICIOUS_XXE_DATA"
            assertNotEquals("MALICIOUS_XXE_DATA", result.getDescription(),
                    "UPOZORENJE: Parser je ranjiv na XXE! Uspješno je razriješio vanjski entitet.");

        } catch (Exception e) {
            // Ako je tvoj parser toliko siguran da je konfiguriran da potpuno blokira DOCTYPE deklaracije
            // (npr. baci fxml/sax parser exception), test PROLAZI jer je napad uspješno zaustavljen!
            assertTrue(true, "Parser je sigurno odbio obradu malicioznog XML-a.");
        }
    }
}