/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.modifiablevariable.util.ModifiableVariableField;
import de.rub.nds.protocol.crypto.signature.SignatureComputations;
import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.modifiableVariable.ModvarHelper;
import de.rub.nds.x509attacker.x509.model.publickey.PublicKeyContent;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import jakarta.xml.bind.ValidationEvent;
import jakarta.xml.bind.ValidationEventHandler;
import jakarta.xml.bind.util.JAXBSource;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.reflections.Reflections;
import org.reflections.util.ClasspathHelper;
import org.reflections.util.ConfigurationBuilder;
import org.reflections.util.FilterBuilder;

public class WorkflowTraceSerializer {

    private static final Logger LOGGER = LogManager.getLogger();

    /** context initialization is expensive, we need to do that only once */
    private static JAXBContext context;

    public static synchronized JAXBContext getJAXBContext() throws JAXBException, IOException {
        if (context == null) {
            // TODO we could do this scanning during building and then just collect the
            // results
            // TODO it would also be good if we didn't have to hardcode the package name
            // here, but I could not get it work without it. Hours wasted: 3
            String packageName = "de.rub";
            Reflections reflections =
                    new Reflections(
                            new ConfigurationBuilder()
                                    .setUrls(ClasspathHelper.forPackage(packageName))
                                    .filterInputsBy(
                                            new FilterBuilder().includePackage(packageName)));
            Set<Class<?>> classes = new HashSet<>();
            classes.add(WorkflowTrace.class);
            classes.addAll(getSerializableSubTypes(reflections, TlsAction.class));
            classes.addAll(getSerializableSubTypes(reflections, DataContainer.class));
            classes.addAll(getSerializableSubTypes(reflections, Asn1Encodable.class));
            classes.addAll(getSerializableSubTypes(reflections, PublicKeyContent.class));
            classes.addAll(getSerializableSubTypes(reflections, VariableModification.class));
            classes.addAll(getSerializableSubTypes(reflections, SignatureComputations.class));

            LOGGER.trace("Registering Classes in JAXBContext of WorkflowTraceSerializer:");
            for (Class<?> tempClass : classes) {
                LOGGER.trace(tempClass.getName());
            }
            context = JAXBContext.newInstance(classes.toArray(new Class[classes.size()]));
        }
        return context;
    }

    private static <T> Set<Class<? extends T>> getSerializableSubTypes(
            Reflections reflections, Class<T> clazz) {
        return reflections.getSubTypesOf(clazz).stream()
                .filter(listed -> !listed.isInterface())
                .collect(Collectors.toSet());
    }

    public static synchronized void setJAXBContext(JAXBContext context)
            throws JAXBException, IOException {
        WorkflowTraceSerializer.context = context;
    }

    /**
     * Writes a WorkflowTrace to a File
     *
     * @param file File to which the WorkflowTrace should be written
     * @param trace WorkflowTrace that should be written
     * @throws FileNotFoundException Is thrown if the File cannot be found
     * @throws JAXBException Is thrown if the Object cannot be serialized
     * @throws IOException Is thrown if the Process doesn't have the rights to write to the File
     */
    public static void write(File file, WorkflowTrace trace)
            throws FileNotFoundException, JAXBException, IOException {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            write(fos, trace);
        }
    }

    /**
     * Writes a serialized WorkflowTrace to string.
     *
     * @param trace WorkflowTrace that should be written
     * @return String containing XML/serialized representation of the WorkflowTrace
     * @throws JAXBException Is thrown if the Object cannot be serialized
     * @throws IOException Is thrown if the Process doesn't have the rights to write to the File
     */
    public static String write(WorkflowTrace trace) throws JAXBException, IOException {
        SilentByteArrayOutputStream bos = new SilentByteArrayOutputStream();
        WorkflowTraceSerializer.write(bos, trace);
        return bos.toString(StandardCharsets.UTF_8);
    }

    /**
     * @param outputStream The OutputStream to which the Trace should be written to.
     * @param workflowTrace The WorkflowTrace that should be written
     * @throws JAXBException JAXBException if the JAXB reports a problem
     * @throws IOException If something goes wrong while writing to the stream
     */
    public static void write(OutputStream outputStream, WorkflowTrace workflowTrace)
            throws JAXBException, IOException {
        context = getJAXBContext();
        try (SilentByteArrayOutputStream xmlOutputStream = new SilentByteArrayOutputStream()) {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            transformer.transform(
                    new JAXBSource(context, workflowTrace), new StreamResult(xmlOutputStream));

            outputStream.write(
                    xmlOutputStream
                            .toString(StandardCharsets.UTF_8)
                            .replaceAll("\r?\n", System.lineSeparator())
                            .getBytes(StandardCharsets.UTF_8));
        } catch (TransformerException E) {
            throw new JAXBException(E);
        }
    }

    /**
     * @param inputStream The InputStream from which the Parameter should be read. Does NOT perform
     *     schema validation
     * @return The deserialized WorkflowTrace
     * @throws JAXBException JAXBException if the JAXB reports a problem
     * @throws IOException If something goes wrong while writing to the stream
     * @throws XMLStreamException If there is a Problem with the XML Stream
     */
    public static WorkflowTrace insecureRead(InputStream inputStream)
            throws JAXBException, IOException, XMLStreamException {
        context = getJAXBContext();
        Unmarshaller unmarshaller = context.createUnmarshaller();
        unmarshaller.setEventHandler(
                event -> {
                    // raise an Exception also on Warnings
                    return false;
                });
        XMLInputFactory xif = XMLInputFactory.newFactory();
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xsr = xif.createXMLStreamReader(inputStream);
        return (WorkflowTrace) unmarshaller.unmarshal(xsr);
    }

    /**
     * Reads a file and does not perform schema validation
     *
     * @param f
     * @return
     */
    public static List<WorkflowTrace> insecureReadFolder(File f) {
        if (f.isDirectory()) {
            ArrayList<WorkflowTrace> list = new ArrayList<>();
            File[] files = f.listFiles();
            if (files == null) {
                return list;
            }
            for (File file : files) {
                if (file.getName().startsWith(".")) {
                    // We ignore the .gitignore File
                    continue;
                }
                WorkflowTrace trace;
                try (FileInputStream fis = new FileInputStream(file)) {
                    trace = WorkflowTraceSerializer.insecureRead(fis);
                    trace.setName(file.getAbsolutePath());
                    list.add(trace);
                } catch (JAXBException | IOException | XMLStreamException ex) {
                    LOGGER.warn("Could not read {} from folder", file.getAbsolutePath());
                    LOGGER.debug(ex);
                }
            }
            return list;
        } else {
            throw new IllegalArgumentException("Cannot read Folder, because its not a Folder");
        }
    }

    /**
     * @param inputStream The InputStream from which the Parameter should be read. Does perform
     *     schema validation
     * @return The deserialized WorkflowTrace
     * @throws JAXBException JAXBException if the JAXB reports a problem
     * @throws IOException If something goes wrong while writing to the stream
     * @throws XMLStreamException If there is a Problem with the XML Stream
     */
    public static WorkflowTrace secureRead(InputStream inputStream)
            throws JAXBException, IOException, XMLStreamException {
        try {
            context = getJAXBContext();
            Unmarshaller unmarshaller = context.createUnmarshaller();

            unmarshaller.setEventHandler(
                    new ValidationEventHandler() {
                        @Override
                        public boolean handleEvent(ValidationEvent event) {
                            // raise an Exception also on Warnings
                            return false;
                        }
                    });

            // String xsd_source =
            //        WorkflowTraceSchemaGenerator.AccumulatingSchemaOutputResolver.mapSystemIds();
            XMLInputFactory xif = XMLInputFactory.newFactory();
            xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            XMLStreamReader xsr = xif.createXMLStreamReader(inputStream);
            /* Deactivated Schema validation
            SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            try (InputStream schemaInputStream =
                    WorkflowTraceSerializer.class.getResourceAsStream("/" + xsd_source)) {
                Schema configSchema = sf.newSchema(new StreamSource(schemaInputStream));
                configSchema.newValidator();
                unmarshaller.setSchema(configSchema);
            }
             */
            WorkflowTrace wt = (WorkflowTrace) unmarshaller.unmarshal(xsr);
            ModvarHelper helper = new ModvarHelper();
            List<ModifiableVariableField> allSentFields =
                    helper.getAllStaticallyConfiguredSentFields(wt);
            for (ModifiableVariableField field : allSentFields) {
                if (field.getModifiableVariable() != null
                        && field.getModifiableVariable().getOriginalValue() != null) {
                    LOGGER.warn(
                            "Your WorkflowTrace still contains original values. These values will be deleted by TLS-Attacker and ignored for any computations. Use Modifications and/or the Config to change the contet of messages");
                    break;
                }
            }
            return wt;
        } catch (IllegalArgumentException | IllegalAccessException ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Reads a folder. Does perform schema validation.
     *
     * @param f
     * @return
     */
    public static List<WorkflowTrace> secureReadFolder(File f) {
        if (f.isDirectory()) {
            LOGGER.debug("Reading WorkflowTraces from folder: {}", f.getAbsolutePath());
            ArrayList<WorkflowTrace> list = new ArrayList<>();
            File[] files = f.listFiles();
            if (files == null) {
                return list;
            }
            for (File file : files) {
                if (file.getName().startsWith(".")) {
                    // We ignore the .gitignore File
                    continue;
                }
                WorkflowTrace trace;
                try (FileInputStream fis = new FileInputStream(file)) {
                    LOGGER.debug("Reading WorkflowTrace from file: {}", file.getAbsolutePath());
                    trace = WorkflowTraceSerializer.secureRead(fis);
                    trace.setName(file.getAbsolutePath());
                    list.add(trace);
                } catch (JAXBException | IOException | XMLStreamException ex) {
                    LOGGER.warn("Could not read {} from Folder.", ex);
                }
            }
            return list;
        } else {
            throw new IllegalArgumentException("Cannot read Folder, because its not a Folder");
        }
    }

    private WorkflowTraceSerializer() {}
}
