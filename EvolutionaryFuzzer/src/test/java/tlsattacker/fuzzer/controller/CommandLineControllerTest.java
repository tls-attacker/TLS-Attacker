/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.controller;

import java.io.IOException;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;
import tlsattacker.fuzzer.agent.BlindAgent;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.exceptions.FuzzerConfigurationException;
import tlsattacker.fuzzer.exceptions.IllegalAnalyzerException;
import tlsattacker.fuzzer.exceptions.IllegalCertificateMutatorException;
import tlsattacker.fuzzer.exceptions.IllegalMutatorException;
import tlsattacker.fuzzer.mutator.SimpleMutator;
import tlsattacker.fuzzer.mutator.certificate.FixedCertificateMutator;
import tlsattacker.fuzzer.server.ServerManager;
import tlsattacker.fuzzer.server.TLSServer;

/**
 * //TODO Dont only check that controller does not crash, check that its actually working
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class CommandLineControllerTest {

    private CommandLineController controller;

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    public CommandLineControllerTest() {
    }

    @Before
    public void setUp() throws IllegalMutatorException, IllegalCertificateMutatorException, IllegalAnalyzerException, IOException, FuzzerConfigurationException {

        EvolutionaryFuzzerConfig config = new EvolutionaryFuzzerConfig();
        config.setOutputFolder(folder.newFolder().getAbsolutePath());
        config.setConfigFolder(folder.newFolder().getAbsolutePath());
        config.createFolders();
        config.setAgent(BlindAgent.optionName);
        config.setMutator(SimpleMutator.optionName);
        config.setCertMutator(FixedCertificateMutator.optionName);
        ServerManager manager = ServerManager.getInstance();
        manager.addServer(new TLSServer(null, "", 0, "", "", "", "", ""));
        controller = new CommandLineController(config);

    }

    /**
     * Test of startFuzzer method, of class CommandLineController.
     */
    @Test
    public void testStartFuzzer() {
        controller.startFuzzer();
        assertTrue(controller.isRunning);
        assertFalse(controller.pool.isStopped());
    }

    /**
     * Test of stopFuzzer method, of class CommandLineController.
     */
    @Test
    public void testStopFuzzer() {
        controller.stopFuzzer();
        assertFalse(controller.isRunning);
        assertTrue(controller.pool.isStopped());
    }

    /**
     * Test of printServerStatus method, of class CommandLineController.
     */
    @Test
    public void testPrintServerStatus() {
        controller.printServerStatus();
    }

    /**
     * Test of dumpEdges method, of class CommandLineController.
     * @throws java.io.IOException
     */
    @Test
    public void testDumpEdges() throws IOException {
        String split[] = new String[2];
        split[0] = "";
        split[1] = folder.newFile().getAbsolutePath();
        controller.dumpEdges(split);
        split = new String[0];
        controller.dumpEdges(split);
        
    }

    /**
     * Test of dumpVertices method, of class CommandLineController.
     * @throws java.io.IOException
     */
    @Test
    public void testDumpVertices() throws IOException {
        String split[] = new String[2];
        split[0] = "";
        split[1] = folder.newFile().getAbsolutePath();
        controller.dumpVertices(split);
        split = new String[0];
        controller.dumpVertices(split);
        
    }

    /**
     * Test of loadGraph method, of class CommandLineController.
     * @throws java.io.IOException
     */
    @Test
    public void testLoadGraph() throws IOException {
        String split[] = new String[2];
        split[0] = "";
        split[1] = folder.newFile().getAbsolutePath();
        controller.saveGraph(split);
        controller.loadGraph(split);
        split = new String[0];
        controller.loadGraph(split);
        
    }

    /**
     * Test of saveGraph method, of class CommandLineController.
     * @throws java.io.IOException
     */
    @Test
    public void testSaveGraph() throws IOException {
        String split[] = new String[2];
        split[0] = "";
        split[1] = folder.newFile().getAbsolutePath();
        controller.saveGraph(split);
        split = new String[0];
        controller.saveGraph(split);
        
    }

    /**
     * Test of printUsage method, of class CommandLineController.
     */
    @Test
    public void testPrintUsage() {
        controller.printUsage();
    }

    /**
     * Test of printStatus method, of class CommandLineController.
     */
    @Test
    public void testPrintStatus() {
        controller.printStatus();
    }

}
