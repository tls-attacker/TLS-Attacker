/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.filter.DefaultFilter;
import de.rub.nds.tlsattacker.core.workflow.filter.Filter;
import static de.rub.nds.tlsattacker.util.FileHelper.inputStreamToString;
import de.rub.nds.tlsattacker.util.tests.SlowTests;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import javax.xml.bind.DataBindingException;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * Find the files for this test at
 * src/test/resources/workflow_trace_serialization_tests-positive
 */
@Category(SlowTests.class)
@RunWith(Parameterized.class)
public class WorkflowTraceNormalizerTestGoodInput {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final String TEST_VECTOR_DIR = "/workflow_trace_serialization_tests-positive";

    /**
     * Run each test with a file from TEST_VECTOR_DIR as parameter.
     *
     * @return
     */
    @Parameters
    public static Collection<Object[]> data() {
        File testVectorDir = new File(WorkflowTraceNormalizerTestGoodInput.class.getResource(TEST_VECTOR_DIR).getFile());

        Collection<Object[]> testVectors = new ArrayList<>();
        for (File tv : testVectorDir.listFiles()) {
            testVectors.add(new Object[] { tv });
        }

        return testVectors;
    }

    @Rule
    public final ExpectedException exception = ExpectedException.none();

    private WorkflowTrace trace;
    private WorkflowTrace origTrace;
    private Config config;
    private Filter filter;
    private WorkflowTraceNormalizer normalizer = new WorkflowTraceNormalizer();
    private String configXml;
    private String traceInputXml;
    private String expectedFilteredXml;
    private String expectedNormalizedXml;
    private File testVector;

    public WorkflowTraceNormalizerTestGoodInput(File testVector) {
        this.testVector = testVector;
    }

    @Before
    public void setup() {
        config = null;
        trace = null;
        traceInputXml = null;
        expectedNormalizedXml = null;
        expectedFilteredXml = null;
    }

    @Test
    public void normalizingGoodInputsSucceeds() throws IOException, JAXBException {
        String fullTvName = testVector.getName();
        String tvName = fullTvName.substring(fullTvName.lastIndexOf("/") + 1);
        loadTestVector(testVector);
        origTrace = WorkflowTrace.copy(trace);

        assertNotNull(config);
        assertNotNull(trace);
        normalizer.normalize(trace, config);
        String actual = WorkflowTraceSerializer.write(trace).trim();
        assertEquals("Normalized output should be fine", actual, expectedNormalizedXml);

        filter = new DefaultFilter(config);
        filter.applyFilter(trace);
        filter.postFilter(trace, origTrace);
        actual = WorkflowTraceSerializer.write(trace).trim();
        assertEquals("Filtered output should be fine", actual, expectedFilteredXml);
    }

    /**
     * Loads a test vector from file. Have a look at the test vectors to see the
     * required format.
     *
     * @param testVectorPath
     */
    private void loadTestVector(File testVectorPath) {
        String testData;
        try {
            testData = inputStreamToString(new FileInputStream(testVectorPath));
        } catch (IOException ex) {
            LOGGER.error("Could not load test file " + testVectorPath + ": " + ex);
            return;
        }

        String testDataSplit[] = testData.split("(?m)#.*$");
        configXml = testDataSplit[1].trim();
        traceInputXml = testDataSplit[2].trim();
        if (testDataSplit.length > 3) {
            expectedNormalizedXml = testDataSplit[3].trim();
            expectedFilteredXml = testDataSplit[4].trim();
        }

        try {
            config = Config.createConfig(new ByteArrayInputStream(configXml.getBytes(StandardCharsets.UTF_8.name())));
        } catch (UnsupportedEncodingException ex) {
            LOGGER.error("Could not load config from test file " + testVectorPath + ": " + ex);
            return;
        }

        try {
            trace = WorkflowTraceSerializer.read(new ByteArrayInputStream(traceInputXml.getBytes(StandardCharsets.UTF_8
                    .name())));
        } catch (JAXBException | IOException | XMLStreamException | DataBindingException ex) {
            LOGGER.error("Could not load workflow trace from test file " + testVectorPath + ": " + ex);
        }

    }

}
