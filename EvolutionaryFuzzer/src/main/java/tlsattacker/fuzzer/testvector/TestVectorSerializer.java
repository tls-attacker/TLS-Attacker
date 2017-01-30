/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.testvector;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModificationFilter;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.tls.util.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.TLSAction;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import java.io.ByteArrayInputStream;
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
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;

/**
 * A helper class to serialize and deserialize TestVectors.
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TestVectorSerializer {

    private static final Logger LOGGER = LogManager.getLogger(TestVectorSerializer.class);

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
            context = JAXBContext.newInstance(TestVector.class, ExtensionMessage.class, WorkflowTrace.class,
                    ProtocolMessage.class, ModificationFilter.class, VariableModification.class,
                    ModifiableVariable.class, ServerCertificateStructure.class, File.class, TLSAction.class);
        }
        return context;
    }

    /**
     * Writes a WorkflowTrace to a File
     *
     * @param file
     *            File to which the TestVector should be written
     * @param vector
     *            TestVector that should be written
     * @throws FileNotFoundException
     *             Is thrown if the File cannot be found
     * @throws JAXBException
     *             Is thrown when the Object cannot be serialized
     * @throws IOException
     *             Is thrown if the Process doesn't have the rights to write to
     *             the File
     */
    public static void write(File file, TestVector vector) throws FileNotFoundException, JAXBException, IOException {
        if (!file.exists()) {
            file.createNewFile();
        }
        FileOutputStream fos = new FileOutputStream(file);
        TestVectorSerializer.write(fos, vector);
    }

    /**
     * Writes a TestVector to an Outputstream
     *
     * @param outputStream
     *            Outputstream to write to
     * @param vector
     *            TestVector to serializ
     * @throws JAXBException
     *             If something goes wrong
     * @throws IOException
     *             If something goes wrong
     */
    public static void write(OutputStream outputStream, TestVector vector) throws JAXBException, IOException {
        context = getJAXBContext();
        Marshaller m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        m.marshal(vector, outputStream);
        outputStream.close();
    }

    /**
     * Reads a TestVector from an InputStream
     *
     * @param inputStream
     *            Inputstream to read from
     * @return Read TestVector
     * @throws JAXBException
     *             If something goes wrong
     * @throws IOException
     *             If something goes wrong
     * @throws XMLStreamException
     *             If something goes wrong
     */
    public static TestVector read(InputStream inputStream) throws JAXBException, IOException, XMLStreamException {
        context = getJAXBContext();
        Unmarshaller m = context.createUnmarshaller();
        XMLInputFactory xif = XMLInputFactory.newFactory();
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xsr = xif.createXMLStreamReader(inputStream);
        TestVector vector = (TestVector) m.unmarshal(xsr);
        inputStream.close();
        return vector;
    }

    /**
     * Reads all TestVectors from a Folder
     *
     * @param f
     *            Folder to read from
     * @return All TestVectors that were readable from the folder
     */
    public static List<TestVector> readFolder(File f) {
        if (f.isDirectory()) {
            ArrayList<TestVector> list = new ArrayList<>();
            for (File file : f.listFiles()) {
                if (file.getName().startsWith(".")) {
                    // We ignore the .gitignore File
                    continue;
                }
                TestVector vector;
                try {
                    vector = TestVectorSerializer.read(new FileInputStream(file));
                    vector.getTrace().setName(file.getAbsolutePath());
                    list.add(vector);
                } catch (XMLStreamException | IOException | JAXBException | java.lang.NoSuchMethodError ex) {
                    LOGGER.info("Could not load file: " + file.getAbsolutePath());
                    LOGGER.debug(ex.getLocalizedMessage(), ex);
                }
            }
            return list;
        } else {
            throw new IllegalArgumentException("Cannot read Folder, because its not a Folder:" + f.getAbsolutePath());
        }

    }

    /**
     * Returns a somehow deep copy of the TestVector. The WorkflowTrace is deep
     * copied and the rest is passed as a reference.
     *
     * @param testVector
     * @return
     * @throws javax.xml.bind.JAXBException
     * @throws java.io.IOException
     * @throws javax.xml.stream.XMLStreamException
     */
    public static TestVector copyTestVector(TestVector testVector) throws JAXBException, IOException,
            XMLStreamException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        WorkflowTraceSerializer.write(stream, testVector.getTrace());
        stream.flush();
        WorkflowTrace copiedTrace = WorkflowTraceSerializer.read(new ByteArrayInputStream(stream.toByteArray()));
        TestVector tempVector = new TestVector(copiedTrace, testVector.getServerKeyCert(),
                testVector.getClientKeyCert(), ExecutorType.TLS, testVector.getParent());
        return tempVector;
    }

    private TestVectorSerializer() {
    }

}
