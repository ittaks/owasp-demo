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
            // OWASP A03:2021 MITIGATION - DEFENSIVE XXE HARDENING
            // Completely disable DTDs (Document Type Definitions) and external entities
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
            // Keep error messages generic to prevent path/system structural leaks
            throw new RuntimeException("Invalid or unsafe file structural format.");
        }
    }
}
