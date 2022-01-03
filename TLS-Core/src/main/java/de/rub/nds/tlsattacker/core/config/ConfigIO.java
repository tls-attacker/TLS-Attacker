/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.config;

import de.rub.nds.tlsattacker.core.config.filter.ConfigDisplayFilter;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.xml.XMLConstants;
import javax.xml.bind.DataBindingException;
import java.nio.charset.StandardCharsets;
import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.ValidationEvent;
import javax.xml.bind.ValidationEventHandler;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.xml.sax.SAXException;

public class ConfigIO {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * context initialization is expensive, we need to do that only once
     */
    private static JAXBContext context;

    static synchronized JAXBContext getJAXBContext() throws JAXBException {
        if (context == null) {
            context = JAXBContext.newInstance(Config.class);
        }
        return context;
    }

    public static void write(Config config, File f) {
        try {
            write(config, new FileOutputStream(f));
        } catch (FileNotFoundException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static void write(Config config, OutputStream os) {
        ByteArrayOutputStream tempStream = new ByteArrayOutputStream();
        JAXB.marshal(config, tempStream);
        try {
            os.write(new String(tempStream.toByteArray()).getBytes(StandardCharsets.ISO_8859_1));
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
            unmarshaller.setEventHandler(new ValidationEventHandler() {
                @Override
                public boolean handleEvent(ValidationEvent event) {
                    // Raise an exception also on warnings
                    return false;
                }
            });
            return read(new FileInputStream(f), unmarshaller);
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        } catch (FileNotFoundException e) {
            throw new IllegalArgumentException("File cannot be found");
        }
    }

    public static Config read(InputStream stream) {
        try {
            Unmarshaller unmarshaller = getJAXBContext().createUnmarshaller();
            // output any anomalies in the given config file
            unmarshaller.setEventHandler(new ValidationEventHandler() {
                @Override
                public boolean handleEvent(ValidationEvent event) {
                    // Raise an exception also on warnings
                    return false;
                }
            });
            return read(stream, unmarshaller);
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Reads the XML from the given inputStream with the provided unmarshaller into a new Config
     * 
     * @param  stream
     *                      The stream that provides the XML structure
     * @param  unmarshaller
     *                      The unmarshaller that will be used during the parsing
     * @return              Config a new Config that contains the parsed values from the inputStream
     */
    private static Config read(InputStream stream, Unmarshaller unmarshaller) {
        if (stream == null) {
            throw new IllegalArgumentException("Stream cannot be null");
        }
        try {
            String xsd_source = ConfigSchemaGenerator.AccumulatingSchemaOutputResolver.mapSystemIds();
            XMLInputFactory xif = XMLInputFactory.newFactory();
            xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            XMLStreamReader xsr = xif.createXMLStreamReader(stream);
            SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema configSchema =
                sf.newSchema(new StreamSource(WorkflowTraceSerializer.class.getResourceAsStream("/" + xsd_source)));
            configSchema.newValidator();
            unmarshaller.setSchema(configSchema);
            Config config = (Config) unmarshaller.unmarshal(xsr);
            return config;
        } catch (XMLStreamException | SAXException | JAXBException e) {
            throw new RuntimeException(e);
        }
    }

    public static Config copy(Config config) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ConfigIO.write(config, byteArrayOutputStream);
        return ConfigIO.read(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()));
    }

    private ConfigIO() {
    }
}
