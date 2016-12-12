/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.mutator;

import de.rub.nds.tlsattacker.tls.protocol.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import java.io.IOException;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.mutator.certificate.CertificateMutator;
import tlsattacker.fuzzer.testvector.TestVector;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class NoneMutatorTest {

    private NoneMutator mutator;
    private CertificateMutator certMutator;
    private EvolutionaryFuzzerConfig config;

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    public NoneMutatorTest() {
    }

    @Before
    public void setUp() throws IOException {
        config = new EvolutionaryFuzzerConfig();
        config.setOutputFolder(tempFolder.newFolder().getAbsolutePath());
        config.setConfigFolder(tempFolder.newFolder().getAbsolutePath());
        config.setArchiveFolder(tempFolder.newFolder().getAbsolutePath());
        certMutator = new tlsattacker.fuzzer.testhelper.UnitTestCertificateMutator();
        mutator = new NoneMutator(config, certMutator);

    }

    /**
     * Test of getNewMutation method, of class NoneMutator.
     */
    @Test
    public void testGetNewMutation() {
        WorkflowTrace trace = new WorkflowTrace();
        TestVector test = new TestVector(trace, certMutator.getServerCertificateStructure(),
                certMutator.getClientCertificateStructure(), ExecutorType.TLS, null);

        TestVector generated = mutator.getNewMutation();
        System.out.println("generated" + generated.toString() + " test" + test.toString());
        assertEquals(generated, test);
        trace.add(new SendAction(new ClientHelloMessage()));
        trace.add(new ReceiveAction(new ArbitraryMessage()));

    }

}
