/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.protocol.TlsMessage;
import java.io.*;
import java.util.Set;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.reflections.Reflections;

public class MessageIO {

    private static final Logger LOGGER = LogManager.getLogger();

    private static JAXBContext context;

    private static synchronized JAXBContext getJAXBContext() throws JAXBException, IOException {
        if (context == null) {
            Reflections reflections = new Reflections("de.rub.nds.tlsattacker.core.protocol.message");
            Set<Class<? extends TlsMessage>> classes = reflections.getSubTypesOf(TlsMessage.class);
            reflections = new Reflections("de.rub.nds.tlsattacker.core.https");
            classes.addAll(reflections.getSubTypesOf(TlsMessage.class));
            Class<? extends TlsMessage>[] classesArray = classes.toArray(new Class[classes.size()]);
            context = JAXBContext.newInstance(classesArray);
        }
        return context;
    }

    public static void write(File file, TlsMessage message)
        throws FileNotFoundException, JAXBException, IOException {
        if (!file.exists()) {
            file.createNewFile();
        }
        FileOutputStream fos = new FileOutputStream(file);
        MessageIO.write(fos, message);
    }

    public static void write(OutputStream outputStream, TlsMessage message) throws JAXBException, IOException {
        context = getJAXBContext();
        Marshaller m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        m.marshal(message, outputStream);
        outputStream.close();
    }

    public static TlsMessage read(InputStream inputStream) throws JAXBException, IOException, XMLStreamException {
        context = getJAXBContext();
        Unmarshaller m = context.createUnmarshaller();
        XMLInputFactory xif = XMLInputFactory.newFactory();
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xsr = xif.createXMLStreamReader(inputStream);
        TlsMessage message = (TlsMessage) m.unmarshal(xsr);
        inputStream.close();
        return message;
    }

    public static TlsMessage copyTlsAction(TlsMessage message)
        throws JAXBException, IOException, XMLStreamException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        MessageIO.write(stream, message);
        stream.flush();
        TlsMessage copiedMessage = MessageIO.read(new ByteArrayInputStream(stream.toByteArray()));
        return copiedMessage;
    }

    private MessageIO() {
    }
}
