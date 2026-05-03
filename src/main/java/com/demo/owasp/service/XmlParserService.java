package com.demo.owasp.service;

import com.demo.owasp.dto.request.TaskFromXmlRequest;
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

            // OWASP A05 / A03 VULNERABILITY
            // External entities NOT disabled → XXE possible
            DocumentBuilder builder = factory.newDocumentBuilder();

            Document doc = builder.parse(file.getInputStream());

            TaskFromXmlRequest dto = new TaskFromXmlRequest();

            dto.setTitle(doc.getElementsByTagName("title").item(0).getTextContent());
            dto.setDescription(doc.getElementsByTagName("description").item(0).getTextContent());

            return dto;

        } catch (Exception e) {
            throw new RuntimeException("Invalid XML");
        }
    }
}
