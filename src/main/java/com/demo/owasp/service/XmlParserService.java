package com.demo.owasp.service;

import com.demo.owasp.dto.TaskFromXmlRequest;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.w3c.dom.Document;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

@Service
public class XmlParserService {

    public TaskFromXmlRequest parse(MultipartFile file) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

            // =========================================================================
            // OWASP A03:2025 MITIGACIJA - OBRAMBENO OČVRŠĆIVANJE OD XXE NAPADA
            // Potpuno onemogućavanje DTD-ova (Document Type Definitions) i vanjskih entiteta.
            // Čak i ako komponenta treće strane ima propust, kôd onemogućava njezinu zloupotrebu.
            // =========================================================================
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);

            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(file.getInputStream());

            TaskFromXmlRequest dto = new TaskFromXmlRequest();

            if (doc.getElementsByTagName("title").getLength() > 0) {
                dto.setTitle(doc.getElementsByTagName("title").item(0).getTextContent());
            }
            if (doc.getElementsByTagName("description").getLength() > 0) {
                dto.setDescription(doc.getElementsByTagName("description").item(0).getTextContent());
            }

            return dto;
        } catch (Exception e) {
            // Poruke o pogrešci ostaju generičke kako bi se spriječilo curenje strukture sustava i putanja
            throw new RuntimeException("Format strukture datoteke je nevažeći ili nesiguran.");
        }
    }
}