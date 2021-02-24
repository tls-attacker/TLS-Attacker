/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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

public class ActionIO {

    // TODO this is a little bit redundant
    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * context initialization is expensive, we need to do that only once
     */
    private static JAXBContext context;

    /**
     * Returns an initialized JaxbContext
     *
     * @return
     * @throws JAXBException
     * @throws IOException
     */
    private static synchronized JAXBContext getJAXBContext() throws JAXBException, IOException {
        if (context == null) {
            Reflections reflections = new Reflections("de.rub.nds.tlsattacker.core.workflow.action");
            Set<Class<? extends TlsAction>> classes = reflections.getSubTypesOf(TlsAction.class);
            Class<? extends TlsAction>[] classesArray = classes.toArray(new Class[classes.size()]);
            context = JAXBContext.newInstance(classesArray);
        }
        return context;
    }

    /**
     * Writes a TlsAction to a File
     *
     * @param file
     * File to which the TestVector should be written
     * @param action
     * TlsAction to serialize
     * @throws FileNotFoundException
     * Is thrown if the File cannot be found
     * @throws JAXBException
     * Is thrown when the Object cannot be serialized
     * @throws IOException
     * Is thrown if the Process doesn't have the rights to write to the File
     */
    public static void write(File file, TlsAction action) throws FileNotFoundException, JAXBException, IOException {
        if (!file.exists()) {
            file.createNewFile();
        }
        FileOutputStream fos = new FileOutputStream(file);
        ActionIO.write(fos, action);
    }

    /**
     * Writes a TlsAction to an Outputstream
     *
     * @param outputStream
     * Outputstream to write to
     * @param action
     * TlsAction to serialize
     * @throws JAXBException
     * If something goes wrong
     * @throws IOException
     * If something goes wrong
     */
    public static void write(OutputStream outputStream, TlsAction action) throws JAXBException, IOException {
        context = getJAXBContext();
        Marshaller m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        m.marshal(action, outputStream);
        outputStream.close();
    }

    /**
     * Reads a TlsAction from an InputStream
     *
     * @param inputStream
     * Inputstream to read from
     * @return Read TlsAction
     * @throws JAXBException
     * If something goes wrong
     * @throws IOException
     * If something goes wrong
     * @throws XMLStreamException
     * If something goes wrong
     */
    public static TlsAction read(InputStream inputStream) throws JAXBException, IOException, XMLStreamException {
        context = getJAXBContext();
        Unmarshaller m = context.createUnmarshaller();
        XMLInputFactory xif = XMLInputFactory.newFactory();
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xsr = xif.createXMLStreamReader(inputStream);
        TlsAction vector = (TlsAction) m.unmarshal(xsr);
        inputStream.close();
        return vector;
    }

    /**
     * Returns a deep copy of the action.
     *
     * @param tlsAction
     * @return
     * @throws javax.xml.bind.JAXBException
     * @throws java.io.IOException
     * @throws javax.xml.stream.XMLStreamException
     */
    public static TlsAction copyTlsAction(TlsAction tlsAction) throws JAXBException, IOException, XMLStreamException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        ActionIO.write(stream, tlsAction);
        stream.flush();
        TlsAction copiedAction = ActionIO.read(new ByteArrayInputStream(stream.toByteArray()));
        return copiedAction;
    }

    private ActionIO() {
    }
}
