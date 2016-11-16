/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.controller;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import tlsattacker.fuzzer.agent.BlindAgent;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.exceptions.IllegalAnalyzerException;
import tlsattacker.fuzzer.exceptions.IllegalCertificateMutatorException;
import tlsattacker.fuzzer.exceptions.IllegalMutatorException;
import tlsattacker.fuzzer.mutator.SimpleMutator;
import tlsattacker.fuzzer.mutator.certificate.FixedCertificateMutator;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CommandLineControllerTest {

    private CommandLineController controller;

    public CommandLineControllerTest() {
    }

    @Before
    public void setUp() throws IllegalMutatorException, IllegalCertificateMutatorException, IllegalAnalyzerException {
        EvolutionaryFuzzerConfig config = new EvolutionaryFuzzerConfig();
        config.setAgent(BlindAgent.optionName);
        config.setMutator(SimpleMutator.optionName);
        config.setCertMutator(FixedCertificateMutator.optionName);
        //controller = new CommandLineController(config);
    }

    /**
     * Test of startFuzzer method, of class CommandLineController.
     */
    @Test
    public void testStartFuzzer() {
    }

    /**
     * Test of stopFuzzer method, of class CommandLineController.
     */
    @Test
    public void testStopFuzzer() {
    }

    /**
     * Test of printServerStatus method, of class CommandLineController.
     */
    @Test
    public void testPrintServerStatus() {
    }

    /**
     * Test of dumpEdges method, of class CommandLineController.
     */
    @Test
    public void testDumpEdges() {
    }

    /**
     * Test of dumpVertices method, of class CommandLineController.
     */
    @Test
    public void testDumpVertices() {
    }

    /**
     * Test of loadGraph method, of class CommandLineController.
     */
    @Test
    public void testLoadGraph() {
    }

    /**
     * Test of saveGraph method, of class CommandLineController.
     */
    @Test
    public void testSaveGraph() {
    }

    /**
     * Test of printUsage method, of class CommandLineController.
     */
    @Test
    public void testPrintUsage() {
    }

    /**
     * Test of printStatus method, of class CommandLineController.
     */
    @Test
    public void testPrintStatus() {
    }

    /**
     * Test of startInterface method, of class CommandLineController.
     */
    @Test
    public void testStartInterface() {
    }

}
