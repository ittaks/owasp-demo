package com.demo.owasp.security;

import com.demo.owasp.dto.request.TaskRequest;
import com.demo.owasp.entity.Task;
import com.demo.owasp.entity.User;
import com.demo.owasp.repository.TaskRepository;
import com.demo.owasp.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class InsecureDesignAttacksTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TaskRepository taskRepository;

    private final ObjectMapper objectMapper = new ObjectMapper();

    // =========================================================================
    // TEST 1: Sprječavanje Excessive Data Exposure (Korištenje DTO-a)
    // =========================================================================
    @Test
    @DisplayName("Dizajn API-ja mora koristiti DTO i ne smije izlagati cijeli domenski objekt korisnika")
    void shouldNotExposeInternalDomainEntityFields() throws Exception {
        // Kreiramo i spremamo korisnika u bazu
        User owner = new User();
        owner.setUsername("testKorisnik");
        owner.setPassword("skrivenaLozinka123");
        owner.setRole("USER");
        owner = userRepository.save(owner);

        // Kreiramo i spremamo zadatak povezan s tim korisnikom
        Task task = new Task();
        task.setTitle("Diplomski zadatak");
        task.setDescription("Analiza dizajna");
        task.setOwner(owner);
        task = taskRepository.save(task);

        // Izvršavamo GET poziv s pravim, generiranim ID-em iz baze
        mockMvc.perform(get("/tasks/" + task.getId())
                        .with(user("testKorisnik").roles("USER"))
                        .with(csrf()))
                .andExpect(status().isOk())
                // Provjeravamo da DTO radi i vraća ispravno mapirano polje
                .andExpect(jsonPath("$.ownerUsername").value("testKorisnik"))
                // KLJUČNO: Provjera da NE izlaže unutarnji entitet baze (lozinka, role itd.)
                .andExpect(jsonPath("$.owner").doesNotExist())
                .andExpect(jsonPath("$.owner.password").doesNotExist());
    }

    // =========================================================================
    // TEST 2: Validacija poslovnog limita (Business Logic Limit / Resource Exhaustion)
    // =========================================================================
    @Test
    @DisplayName("Sustav moet odbiti kreiranje zadataka ako se prijeđe limit od 100 po korisniku")
    void shouldEnforceBusinessLogicLimit() throws Exception {
        // Kreiramo testnog korisnika
        User owner = new User();
        owner.setUsername("limitKorisnik");
        owner.setPassword("pass");
        owner.setRole("USER");
        owner = userRepository.save(owner);

        // Napunimo bazu do maksimalnog limita (100 zadataka)
        for (int i = 0; i < 100; i++) {
            Task t = new Task();
            t.setTitle("Automated Task " + i);
            t.setOwner(owner);
            taskRepository.save(t);
        }

        // Pripremamo 101. zahtjev koji simulira Denial of Wallet / Resource Exhaustion napad
        TaskRequest request = new TaskRequest();
        request.setTitle("Preko limita");
        request.setDescription("Ovaj zahtjev mora biti blokiran poslovnom logikom");

        mockMvc.perform(post("/tasks")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                        .with(user("limitKorisnik").roles("USER"))
                        .with(csrf()))
                // Budući da servis za limit baca IllegalStateException, GlobalExceptionHandler
                // to hvata kao 500 Internal Server Error (što je sigurno i očekivano ponašanje)
                .andExpect(status().isInternalServerError());
    }

    // =========================================================================
    // TEST 3: Unrestricted Upload of File with Dangerous Type (Arhitektonska provjera)
    // =========================================================================
    @Test
    @DisplayName("Upload datoteke mora odbiti tipove koji nisu validne XML strukture")
    void shouldRejectNonXmlMultipartFiles() throws Exception {
        // Kreiramo lažni zlonamjerni skriptni fajl (npr. .sh) zamaskiran kao upload
        MockMultipartFile maliciousFile = new MockMultipartFile(
                "file",
                "attack.sh",
                "application/x-sh",
                "echo 'malicious exploit'".getBytes()
        );

        // ISPRAVLJENO: Putanja promijenjena na "/tasks/upload" koja odgovara novom endpointu u kontroleru
        mockMvc.perform(multipart("/tasks/upload")
                        .file(maliciousFile)
                        .with(user("testKorisnik").roles("USER"))
                        .with(csrf()))
                // Očekujemo 400 Bad Request jer smo u GlobalExceptionHandler dodali handler za IllegalArgumentException
                .andExpect(status().isBadRequest());
    }
}