package tlsattacker.fuzzer.mutator;

import tlsattacker.fuzzer.mutator.certificate.CertificateMutator;
import tlsattacker.fuzzer.mutator.Mutator;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.config.mutator.SimpleMutatorConfig;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.util.Random;
import java.util.logging.Logger;
import tlsattacker.fuzzer.testvector.TestVector;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.logging.Level;
import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import tlsattacker.fuzzer.helper.GitIgnoreFileFilter;
import tlsattacker.fuzzer.testvector.TestVectorSerializer;

/**
 * A mutator implementation that does not modify the TestVectors
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class NoneMutator extends Mutator {

    /**
     * The name of the Mutator when referred by command line
     */
    public static final String optionName = "none";

    /**
     * The config to use
     */
    private final SimpleMutatorConfig simpleConfig;

    public NoneMutator(EvolutionaryFuzzerConfig evoConfig, CertificateMutator certMutator) {
        super(evoConfig, certMutator);
        File f = new File(evoConfig.getMutatorConfigFolder() + "simple.conf");
        if (f.exists()) {
            simpleConfig = JAXB.unmarshal(f, SimpleMutatorConfig.class);
        } else {
            simpleConfig = new SimpleMutatorConfig();
            JAXB.marshal(simpleConfig, f);
        }
    }

    /**
     * Returns a random TestVector and does not modify it
     * 
     * @return A random TestVecot
     */
    @Override
    public TestVector getNewMutation() {
        Random r = new Random();
        // chose a random trace from the list
        TestVector tempVector = null;
        WorkflowTrace trace = null;

        if (goodVectorsExist()) {
            try {
                tempVector = chooseRandomTestVectorFromFolder(new File("data/good/"));
            } catch (IOException | JAXBException | XMLStreamException ex) {
                LOG.log(Level.SEVERE, "Could not read good TestVector", ex);
            }
        } else if (archiveVectorsExist()) {
            try {
                tempVector = chooseRandomTestVectorFromFolder(new File("archive/"));
            } catch (IOException | JAXBException | XMLStreamException ex) {
                LOG.log(Level.SEVERE, "Could not read archive TestVector", ex);
            }
        }
        if (tempVector == null) {
            tempVector = new TestVector(new WorkflowTrace(), certMutator.getServerCertificateStructure(),
                    certMutator.getClientCertificateStructure(), config.getActionExecutorConfig()
                            .getRandomExecutorType(), null);
        }
        tempVector.getTrace().reset();
        tempVector.getTrace().makeGeneric();
        return tempVector;

    }

    private static final Logger LOG = Logger.getLogger(NoneMutator.class.getName());
}
