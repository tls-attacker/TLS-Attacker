/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;
import java.io.*;
import java.util.Set;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.reflections.Reflections;

public class MessageIO {

    private static final Logger LOGGER = LogManager.getLogger();

    private static JAXBContext context;

    private static synchronized JAXBContext getJAXBContext() throws JAXBException {
        if (context == null) {
            Reflections reflections =
                    new Reflections("de.rub.nds.tlsattacker.core.protocol.message");
            Set<Class<? extends ProtocolMessage>> classes =
                    reflections.getSubTypesOf(ProtocolMessage.class);
            reflections = new Reflections("de.rub.nds.tlsattacker.core.https");
            classes.addAll(reflections.getSubTypesOf(ProtocolMessage.class));
            Class<? extends ProtocolMessage>[] classesArray =
                    classes.toArray(new Class[classes.size()]);
            context = JAXBContext.newInstance(classesArray);
        }
        return context;
    }

    public static void write(File file, ProtocolMessage message) throws JAXBException, IOException {
        assert file.exists() || file.createNewFile();
        try (FileOutputStream fos = new FileOutputStream(file)) {
            MessageIO.write(fos, message);
        }
    }

    public static void write(OutputStream outputStream, ProtocolMessage message)
            throws JAXBException, IOException {
        context = getJAXBContext();
        Marshaller m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        m.marshal(message, outputStream);
    }

    public static ProtocolMessage read(InputStream inputStream)
            throws JAXBException, IOException, XMLStreamException {
        context = getJAXBContext();
        Unmarshaller m = context.createUnmarshaller();
        XMLInputFactory xif = XMLInputFactory.newFactory();
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xsr = xif.createXMLStreamReader(inputStream);
        return (ProtocolMessage) m.unmarshal(xsr);
    }

    public static ProtocolMessage copyTlsAction(ProtocolMessage message)
            throws JAXBException, IOException, XMLStreamException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        MessageIO.write(stream, message);
        stream.flush();
        return MessageIO.read(new ByteArrayInputStream(stream.toByteArray()));
    }

    private MessageIO() {}
}
