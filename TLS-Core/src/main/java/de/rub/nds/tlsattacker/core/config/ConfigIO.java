/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config;

import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.tlsattacker.core.config.filter.ConfigDisplayFilter;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import jakarta.xml.bind.JAXB;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import jakarta.xml.bind.ValidationEvent;
import jakarta.xml.bind.ValidationEventHandler;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

public class ConfigIO {

    /** context initialization is expensive, we need to do that only once */
    private static JAXBContext context;

    static synchronized JAXBContext getJAXBContext() throws JAXBException {
        if (context == null) {
            context =
                    JAXBContext.newInstance(
                            Config.class, X509CertificateConfig.class, X500AttributeType.class);
        }
        return context;
    }

    public static void write(Config config, File f) {
        try (FileOutputStream fs = new FileOutputStream(f)) {
            write(config, fs);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static void write(Config config, OutputStream os) {
        SilentByteArrayOutputStream tempStream = new SilentByteArrayOutputStream();
        JAXB.marshal(config, tempStream);
        try {
            os.write(
                    tempStream
                            .toString(StandardCharsets.UTF_8)
                            .replaceAll("\r?\n", System.lineSeparator())
                            .getBytes(StandardCharsets.UTF_8));
        } catch (IOException ex) {
            throw new RuntimeException("Could not format XML");
        }
    }

    public static void write(Config config, File f, ConfigDisplayFilter filter) {
        Config filteredConfig = copy(config);
        filter.applyFilter(filteredConfig);
        write(filteredConfig, f);
    }

    public static void write(Config config, OutputStream os, ConfigDisplayFilter filter) {
        Config filteredConfig = copy(config);
        filter.applyFilter(filteredConfig);
        write(filteredConfig, os);
    }

    public static Config read(File f) {
        try {
            Unmarshaller unmarshaller = getJAXBContext().createUnmarshaller();
            // output any anomalies in the given config file
            unmarshaller.setEventHandler(
                    new ValidationEventHandler() {
                        @Override
                        public boolean handleEvent(ValidationEvent event) {
                            // Raise an exception also on warnings
                            return false;
                        }
                    });
            try (FileInputStream fis = new FileInputStream(f)) {
                return read(fis, unmarshaller);
            }
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new IllegalArgumentException("File cannot be read");
        }
    }

    public static Config read(InputStream stream) {
        try {
            Unmarshaller unmarshaller = getJAXBContext().createUnmarshaller();
            // output any anomalies in the given config file
            unmarshaller.setEventHandler(
                    event -> {
                        // Raise an exception also on warnings
                        return false;
                    });
            return read(stream, unmarshaller);
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Reads the XML from the given inputStream with the provided unmarshaller into a new Config
     *
     * @param stream The stream that provides the XML structure
     * @param unmarshaller The unmarshaller that will be used during the parsing
     * @return Config a new Config that contains the parsed values from the inputStream
     */
    private static Config read(InputStream stream, Unmarshaller unmarshaller) {
        if (stream == null) {
            throw new IllegalArgumentException("Stream cannot be null");
        }
        try {
            // String xsd_source =
            //        ConfigSchemaGenerator.AccumulatingSchemaOutputResolver.mapSystemIds();
            XMLInputFactory xif = XMLInputFactory.newFactory();
            xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            XMLStreamReader xsr = xif.createXMLStreamReader(stream);
            /*
            SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            try (InputStream schemaInputStream =
                    WorkflowTraceSerializer.class.getResourceAsStream("/" + xsd_source)) {
                Schema configSchema = sf.newSchema(new StreamSource(schemaInputStream));
                configSchema.newValidator();
                unmarshaller.setSchema(configSchema);
            }
            */
            return (Config) unmarshaller.unmarshal(xsr);
        } catch (XMLStreamException | JAXBException e) {
            throw new RuntimeException(e);
        }
    }

    public static Config copy(Config config) {
        SilentByteArrayOutputStream byteArrayOutputStream = new SilentByteArrayOutputStream();
        write(config, byteArrayOutputStream);
        return read(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()));
    }

    private ConfigIO() {}
}
