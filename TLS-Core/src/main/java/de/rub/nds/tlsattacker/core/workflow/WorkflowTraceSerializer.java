/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.modifiablevariable.util.ModifiableVariableField;
import de.rub.nds.tlsattacker.core.workflow.modifiableVariable.ModvarHelper;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.ValidationEvent;
import javax.xml.bind.ValidationEventHandler;
import javax.xml.bind.util.JAXBSource;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.xml.sax.SAXException;

public class WorkflowTraceSerializer {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * context initialization is expensive, we need to do that only once
     */
    private static JAXBContext context;

    static synchronized JAXBContext getJAXBContext() throws JAXBException, IOException {
        if (context == null) {
            context = JAXBContext.newInstance(WorkflowTrace.class);
        }
        return context;
    }

    /**
     * Writes a WorkflowTrace to a File
     *
     * @param  file
     *                               File to which the WorkflowTrace should be written
     * @param  trace
     *                               WorkflowTrace that should be written
     * @throws FileNotFoundException
     *                               Is thrown if the File cannot be found
     * @throws JAXBException
     *                               Is thrown if the Object cannot be serialized
     * @throws IOException
     *                               Is thrown if the Process doesn't have the rights to write to the File
     */
    public static void write(File file, WorkflowTrace trace) throws FileNotFoundException, JAXBException, IOException {
        FileOutputStream fos = new FileOutputStream(file);
        WorkflowTraceSerializer.write(fos, trace);
    }

    /**
     * Writes a serialized WorkflowTrace to string.
     *
     * @param  trace
     *                       WorkflowTrace that should be written
     * @return               String containing XML/serialized representation of the WorkflowTrace
     * @throws JAXBException
     *                       Is thrown if the Object cannot be serialized
     * @throws IOException
     *                       Is thrown if the Process doesn't have the rights to write to the File
     */
    public static String write(WorkflowTrace trace) throws JAXBException, IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        WorkflowTraceSerializer.write(bos, trace);
        return bos.toString("UTF-8");
    }

    /**
     * @param  outputStream
     *                       The OutputStream to which the Trace should be written to.
     * @param  workflowTrace
     *                       The WorkflowTrace that should be written
     * @throws JAXBException
     *                       JAXBException if the JAXB reports a problem
     * @throws IOException
     *                       If something goes wrong while writing to the stream
     */
    public static void write(OutputStream outputStream, WorkflowTrace workflowTrace) throws JAXBException, IOException {
        context = getJAXBContext();
        try (ByteArrayOutputStream xmlOutputStream = new ByteArrayOutputStream()) {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            transformer.transform(new JAXBSource(context, workflowTrace), new StreamResult(xmlOutputStream));

            String xml_text = xmlOutputStream.toString();
            // and we modify all line separators to the system dependant line separator
            xml_text = xml_text.replaceAll("\r?\n", System.lineSeparator());
            outputStream.write(xml_text.getBytes());
        } catch (TransformerException E) {
            LOGGER.debug(E.getStackTrace());
        }
        outputStream.close();
    }

    /**
     * @param  inputStream
     *                            The InputStream from which the Parameter should be read. Does NOT perform schema
     *                            validation
     * @return                    The deserialized WorkflowTrace
     * @throws JAXBException
     *                            JAXBException if the JAXB reports a problem
     * @throws IOException
     *                            If something goes wrong while writing to the stream
     * @throws XMLStreamException
     *                            If there is a Problem with the XML Stream
     */
    public static WorkflowTrace insecureRead(InputStream inputStream)
        throws JAXBException, IOException, XMLStreamException {
        context = getJAXBContext();
        Unmarshaller unmarshaller = context.createUnmarshaller();
        unmarshaller.setEventHandler(new ValidationEventHandler() {
            @Override
            public boolean handleEvent(ValidationEvent event) {
                // raise an Exception also on Warnings
                return false;
            }
        });
        XMLInputFactory xif = XMLInputFactory.newFactory();
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xsr = xif.createXMLStreamReader(inputStream);
        WorkflowTrace wt = (WorkflowTrace) unmarshaller.unmarshal(xsr);
        inputStream.close();
        return wt;
    }

    /**
     * Reads a file and does not perform schema validation
     *
     * @param  f
     * @return
     */
    public static List<WorkflowTrace> insecureReadFolder(File f) {
        if (f.isDirectory()) {
            ArrayList<WorkflowTrace> list = new ArrayList<>();
            for (File file : f.listFiles()) {
                if (file.getName().startsWith(".")) {
                    // We ignore the .gitignore File
                    continue;
                }
                WorkflowTrace trace;
                try {
                    trace = WorkflowTraceSerializer.insecureRead(new FileInputStream(file));
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

    /**
     * @param  inputStream
     *                            The InputStream from which the Parameter should be read. Does perform schema
     *                            validation
     * @return                    The deserialized WorkflowTrace
     * @throws JAXBException
     *                            JAXBException if the JAXB reports a problem
     * @throws IOException
     *                            If something goes wrong while writing to the stream
     * @throws XMLStreamException
     *                            If there is a Problem with the XML Stream
     */
    public static WorkflowTrace secureRead(InputStream inputStream)
        throws JAXBException, IOException, XMLStreamException {
        try {
            context = getJAXBContext();
            Unmarshaller unmarshaller = context.createUnmarshaller();

            unmarshaller.setEventHandler(new ValidationEventHandler() {
                @Override
                public boolean handleEvent(ValidationEvent event) {
                    // raise an Exception also on Warnings
                    return false;
                }
            });

            String xsd_source = WorkflowTraceSchemaGenerator.AccumulatingSchemaOutputResolver.mapSystemIds();
            XMLInputFactory xif = XMLInputFactory.newFactory();
            xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            XMLStreamReader xsr = xif.createXMLStreamReader(inputStream);

            SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema workflowTraceSchema =
                sf.newSchema(new StreamSource(WorkflowTraceSerializer.class.getResourceAsStream("/" + xsd_source)));
            workflowTraceSchema.newValidator();
            unmarshaller.setSchema(workflowTraceSchema);
            WorkflowTrace wt = (WorkflowTrace) unmarshaller.unmarshal(xsr);
            ModvarHelper helper = new ModvarHelper();
            List<ModifiableVariableField> allSentFields = helper.getAllSentFields(wt);
            for (ModifiableVariableField field : allSentFields) {
                if (field.getModifiableVariable() != null && field.getModifiableVariable().getOriginalValue() != null) {
                    LOGGER.warn(
                        "Your WorkflowTrace still contains original values. These values will be deleted by TLS-Attacker and ignored for any computations. Use Modifications and/or the Config to change the contet of messages");
                    break;
                }
            }
            inputStream.close();
            return wt;
        } catch (IllegalArgumentException | IllegalAccessException | SAXException ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Reads a folder. Does perform schema validation.
     *
     * @param  f
     * @return
     */
    public static List<WorkflowTrace> secureReadFolder(File f) {
        if (f.isDirectory()) {
            ArrayList<WorkflowTrace> list = new ArrayList<>();
            for (File file : f.listFiles()) {
                if (file.getName().startsWith(".")) {
                    // We ignore the .gitignore File
                    continue;
                }
                WorkflowTrace trace;
                try {
                    trace = WorkflowTraceSerializer.secureRead(new FileInputStream(file));
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
