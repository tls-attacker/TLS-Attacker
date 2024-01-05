/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow;

import static de.rub.nds.tlsattacker.util.FileHelper.inputStreamToString;
import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.workflow.filter.DefaultFilter;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import jakarta.xml.bind.JAXBException;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Stream;
import javax.xml.stream.XMLStreamException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Special tests for WorkflowTraceNormalizer. Tests are currently only defined in
 * WorkflowTraceNormalizerTest{Good,Bad}Input, add special tests here.
 */
public class WorkflowTraceNormalizerTest {

    private static final String BAD_INPUT_TEST_VECTOR_DIR =
            "/workflow_trace_serialization_tests-negative";

    private static final String GOOD_INPUT_TEST_VECTOR_DIR =
            "/workflow_trace_serialization_tests-positive";

    private Config config;

    private WorkflowTrace trace;

    private String expectedNormalizedXml;

    private String expectedFilteredXml;

    private WorkflowTraceNormalizer normalizer;

    @BeforeEach
    public void setUp() {
        normalizer = new WorkflowTraceNormalizer();
    }

    public static Stream<File> provideGoodInputTestVectors() {
        File testVectorDir = getResource(GOOD_INPUT_TEST_VECTOR_DIR);
        return Arrays.stream(Objects.requireNonNull(testVectorDir.listFiles()));
    }

    private static File getResource(String path) {
        File testVectorDir = null;
        try {
            testVectorDir =
                    new File(
                            URLDecoder.decode(
                                    WorkflowTraceNormalizerTest.class.getResource(path).getFile(),
                                    "UTF-8"));
        } catch (UnsupportedEncodingException ex) {
            fail("Failed to decode test vector path");
        }
        return testVectorDir;
    }

    @ParameterizedTest
    @MethodSource("provideGoodInputTestVectors")
    @Tag(TestCategories.SLOW_TEST)
    public void testNormalizingGoodInputsSucceeds(File testVector)
            throws IOException, JAXBException, XMLStreamException {
        loadTestVector(testVector);
        WorkflowTrace origTrace = WorkflowTrace.copy(trace);

        assertNotNull(config);
        assertNotNull(trace);

        normalizer.normalize(trace, config);
        String actual = WorkflowTraceSerializer.write(trace).trim();
        assertEquals(expectedNormalizedXml, actual, "Normalized output should be fine");

        DefaultFilter filter = new DefaultFilter(config);
        filter.applyFilter(trace);
        filter.postFilter(trace, origTrace);
        actual = WorkflowTraceSerializer.write(trace).trim();
        assertEquals(expectedFilteredXml, actual, "Filtered output should be fine");
    }

    public static Stream<File> provideBadInputTestVectors() {
        File testVectorDir = getResource(BAD_INPUT_TEST_VECTOR_DIR);
        return Arrays.stream(Objects.requireNonNull(testVectorDir.listFiles()));
    }

    @ParameterizedTest
    @MethodSource("provideBadInputTestVectors")
    @Tag(TestCategories.SLOW_TEST)
    public void testNormalizingBadInputFails(File testVector)
            throws XMLStreamException, JAXBException, IOException {
        loadTestVector(testVector);
        WorkflowTraceNormalizer normalizer = new WorkflowTraceNormalizer();
        ConfigurationException exception =
                assertThrows(
                        ConfigurationException.class, () -> normalizer.normalize(trace, config));
        assertTrue(exception.getMessage().startsWith("Workflow trace not well defined."));
    }

    /**
     * Loads a test vector from file. Have a look at the test vectors to see the required format.
     *
     * @param testVector
     */
    private void loadTestVector(File testVector)
            throws IOException, XMLStreamException, JAXBException {
        String testData;
        try (FileInputStream fis = new FileInputStream(testVector)) {
            testData = inputStreamToString(fis);
        }
        String[] testDataSplit = testData.split("(?m)#.*$");
        String configXml = testDataSplit[1].trim();
        String traceInputXml = testDataSplit[2].trim();
        if (testDataSplit.length > 3) {
            expectedNormalizedXml = testDataSplit[3].trim();
            expectedFilteredXml = testDataSplit[4].trim();
        }
        config =
                Config.createConfig(
                        new ByteArrayInputStream(configXml.getBytes(StandardCharsets.UTF_8)));
        trace =
                WorkflowTraceSerializer.secureRead(
                        new ByteArrayInputStream(traceInputXml.getBytes(StandardCharsets.UTF_8)));
    }
}
