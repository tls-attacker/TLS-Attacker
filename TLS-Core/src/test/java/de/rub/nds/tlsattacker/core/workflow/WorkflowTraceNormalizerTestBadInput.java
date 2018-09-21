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
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
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
 * src/test/resources/workflow_trace_serialization_tests-negative
 */
@Category(SlowTests.class)
@RunWith(Parameterized.class)
public class WorkflowTraceNormalizerTestBadInput {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String TEST_VECTOR_DIR = "/worklfow_trace_serialization_tests-negative";

    /**
     * Run each test with a file from TEST_VECTOR_DIR as parameter.
     *
     * @return
     */
    @Parameters
    public static Collection<Object[]> data() {
        File testVectorDir = new File(WorkflowTraceNormalizerTestBadInput.class.getResource(TEST_VECTOR_DIR).getFile());

        Collection<Object[]> testVectors = new ArrayList<>();
        for (File tv : testVectorDir.listFiles()) {
            testVectors.add(new Object[] { tv });
        }

        return testVectors;
    }

    @Rule
    public final ExpectedException exception = ExpectedException.none();

    private WorkflowTrace trace;
    private WorkflowTrace filteredTrace;
    private Config config;
    private Filter filter;
    private WorkflowTraceNormalizer normalizer = new WorkflowTraceNormalizer();
    private String configXml;
    private String traceInputXml;
    private String expectedNormalizedXml;
    private String expectedFilteredXml;
    private File testVector;

    public WorkflowTraceNormalizerTestBadInput(File testVector) {
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

    /**
     * Test that attempts to normalize bad workflow traces throws proper
     * exceptions.
     *
     * TODO: This could be more fine grained. I.e. split the test into multiple
     * sub tests that test a particular category of bad inputs. This would
     * enable testing the more detailed exception messages.
     */
    @Test
    public void normalizingBadInputsFails() {
        String fullTvName = testVector.getName();
        String tvName = fullTvName.substring(fullTvName.lastIndexOf("/") + 1);
        loadTestVector(testVector);

        exception.expect(ConfigurationException.class);
        exception.expectMessage("Workflow trace not well defined.");
        normalizer.normalize(trace, config);
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
