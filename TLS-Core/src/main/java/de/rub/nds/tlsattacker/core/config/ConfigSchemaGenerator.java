/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config;

import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.SchemaOutputResolver;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;
import javax.xml.transform.Result;
import javax.xml.transform.stream.StreamResult;
import org.apache.commons.lang3.StringUtils;

public class ConfigSchemaGenerator {

    private static final String ROOT_NS = "";

    private static final String NO_NS = "__NO__NS";

    public static void main(String[] args) {
        try {
            File outputDirectory = new File(args[0]);
            assert outputDirectory.exists() || outputDirectory.mkdirs();
            generateSchema(outputDirectory);
        } catch (IOException | JAXBException e) {
            e.printStackTrace();
        }
    }

    private static void generateSchema(File outputDirectory) throws IOException, JAXBException {
        AccumulatingSchemaOutputResolver sor = new AccumulatingSchemaOutputResolver();
        ConfigIO.getJAXBContext().generateSchema(sor);
        for (Map.Entry<String, StringWriter> e : sor.getSchemaWriters().entrySet()) {
            String systemId = sor.getSystemIds().get(e.getKey());
            File f = new File(outputDirectory, systemId);
            try (FileWriter w = new FileWriter(f)) {
                System.out.printf("Writing %s to %s%n", e.getKey(), f.getAbsolutePath());
                w.write(e.getValue().toString().replaceAll("\r?\n", System.lineSeparator()));
            }
        }
    }

    public static class AccumulatingSchemaOutputResolver extends SchemaOutputResolver {
        public static String mapSystemIds() {
            return "Config.xsd";
        }

        private final Map<String, StringWriter> schemaWriters = new HashMap<>();
        private final Map<String, String> systemIds = new HashMap<>();

        public Result createOutput(String namespaceURI, String suggestedFileName)
                throws IOException {
            String ns = StringUtils.isBlank(namespaceURI) ? NO_NS : namespaceURI;
            schemaWriters.put(ns, new StringWriter());
            String systemId = mapSystemIds();
            systemIds.put(ns, systemId);
            StreamResult result = new StreamResult(schemaWriters.get(ns));
            result.setSystemId(systemId);
            return result;
        }

        public Map<String, StringWriter> getSchemaWriters() {
            return schemaWriters;
        }

        public Map<String, String> getSystemIds() {
            return systemIds;
        }
    }
}
