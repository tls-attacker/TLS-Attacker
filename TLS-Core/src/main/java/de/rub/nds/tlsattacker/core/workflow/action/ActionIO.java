/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;
import java.io.*;
import java.util.HashSet;
import java.util.Set;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.reflections.Reflections;
import org.reflections.util.ClasspathHelper;
import org.reflections.util.ConfigurationBuilder;
import org.reflections.util.FilterBuilder;

public class ActionIO {

    private static final Logger LOGGER = LogManager.getLogger();

    private static JAXBContext context;

    private static synchronized JAXBContext getJAXBContext() throws JAXBException {
        if (context == null) {
            String packageName = "de.rub";
            Reflections reflections =
                    new Reflections(
                            new ConfigurationBuilder()
                                    .setUrls(ClasspathHelper.forPackage(packageName))
                                    .filterInputsBy(
                                            new FilterBuilder().includePackage(packageName)));
            Set<Class<? extends TlsAction>> tlsActionClasses =
                    reflections.getSubTypesOf(TlsAction.class);
            Set<Class<?>> classes = new HashSet<>();
            classes.add(WorkflowTrace.class);
            classes.addAll(tlsActionClasses);

            Set<Class<? extends DataContainer>> dataContainers =
                    reflections.getSubTypesOf(DataContainer.class);
            classes.addAll(dataContainers);
            LOGGER.debug("Registering Classes in JAXBContext of ActionIO:");
            for (Class tempClass : classes) {
                LOGGER.debug(tempClass.getName());
            }
            context = JAXBContext.newInstance(classes.toArray(new Class[classes.size()]));
        }
        return context;
    }

    public static void write(File file, TlsAction action) throws JAXBException, IOException {
        assert file.exists() || file.createNewFile();
        try (FileOutputStream fos = new FileOutputStream(file)) {
            ActionIO.write(fos, action);
        }
    }

    public static void write(OutputStream outputStream, TlsAction action)
            throws JAXBException, IOException {
        context = getJAXBContext();
        Marshaller m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        m.marshal(action, outputStream);
    }

    public static TlsAction read(InputStream inputStream)
            throws JAXBException, IOException, XMLStreamException {
        context = getJAXBContext();
        Unmarshaller m = context.createUnmarshaller();
        XMLInputFactory xif = XMLInputFactory.newFactory();
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xsr = xif.createXMLStreamReader(inputStream);
        return (TlsAction) m.unmarshal(xsr);
    }

    public static TlsAction copyTlsAction(TlsAction tlsAction)
            throws JAXBException, IOException, XMLStreamException {
        SilentByteArrayOutputStream stream = new SilentByteArrayOutputStream();
        ActionIO.write(stream, tlsAction);
        stream.flush();
        return ActionIO.read(new ByteArrayInputStream(stream.toByteArray()));
    }

    private ActionIO() {}
}
