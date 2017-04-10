/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.util;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModificationFilter;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.tls.workflow.action.TLSAction;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class WorkflowTraceSerializer {

    static final Logger LOGGER = LogManager.getLogger("WorkflowTraceSerializer");

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
    private static JAXBContext getJAXBContext() throws JAXBException, IOException {
        if (context == null) {
            context = JAXBContext.newInstance(ExtensionMessage.class, WorkflowTrace.class, ProtocolMessage.class,
                    ModificationFilter.class, VariableModification.class, ModifiableVariable.class, TLSAction.class,
                    SendAction.class, ReceiveAction.class);
        }
        return context;
    }

    /**
     * Writes a WorkflowTrace to a File
     *
     * @param file
     *            File to which the WorkflowTrace should be written
     * @param trace
     *            WorkflowTrace that should be written
     * @throws FileNotFoundException
     *             Is thrown if the File cannot be found
     * @throws JAXBException
     *             Is thrown if the Object cannot be serialized
     * @throws IOException
     *             Is thrown if the Process doesn't have the rights to write to
     *             the File
     */
    public static void write(File file, WorkflowTrace trace) throws FileNotFoundException, JAXBException, IOException {
        FileOutputStream fos = new FileOutputStream(file);

        WorkflowTraceSerializer.write(fos, trace);

    }

    /**
     *
     * @param outputStream
     * @param workflowTrace
     * @throws JAXBException
     * @throws IOException
     */
    public static void write(OutputStream outputStream, WorkflowTrace workflowTrace) throws JAXBException, IOException {
        context = getJAXBContext();
        Marshaller m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        m.marshal(workflowTrace, outputStream);
        outputStream.close();
    }

    /**
     *
     * @param inputStream
     * @return
     * @throws JAXBException
     * @throws IOException
     * @throws XMLStreamException
     */
    public static WorkflowTrace read(InputStream inputStream) throws JAXBException, IOException, XMLStreamException {
        context = getJAXBContext();
        Unmarshaller m = context.createUnmarshaller();

        XMLInputFactory xif = XMLInputFactory.newFactory();
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xsr = xif.createXMLStreamReader(inputStream);

        WorkflowTrace wt = (WorkflowTrace) m.unmarshal(xsr);
        inputStream.close();
        return wt;
    }

    public static List<WorkflowTrace> readFolder(File f) {
        if (f.isDirectory()) {
            ArrayList<WorkflowTrace> list = new ArrayList<>();
            for (File file : f.listFiles()) {
                if (file.getName().startsWith(".")) {
                    // We ignore the .gitignore File
                    continue;
                }
                WorkflowTrace trace;
                try {
                    trace = WorkflowTraceSerializer.read(new FileInputStream(file));
                    trace.setName(file.getAbsolutePath());
                    list.add(trace);
                } catch (JAXBException | IOException | XMLStreamException ex) {
                    LOGGER.warn("Could not read " + file.getAbsolutePath() + " from Folder.");
                    LOGGER.debug(ex.getLocalizedMessage(), ex);
                }
            }
            return list;
        } else {
            throw new IllegalArgumentException("Cannot read Folder, because its not a Folder");
        }

    }

    private WorkflowTraceSerializer() {

    }

}
