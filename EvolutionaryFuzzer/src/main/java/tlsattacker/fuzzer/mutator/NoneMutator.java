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
     *
     */
    private static final Logger LOG = Logger.getLogger(NoneMutator.class.getName());

    /**
     *
     */
    public static final String optionName = "none";

    /**
     *
     */
    private final SimpleMutatorConfig simpleConfig;

    /**
     * 
     * @param config
     * @param certMutator
     */
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
     * 
     * @return
     */
    private boolean goodVectorsExist() {
	File f = new File("data/good/");
	return f.listFiles().length > 0;

    }

    /**
     * 
     * @return
     */
    private boolean archiveVectorsExist() {
	File f = new File("archive/");
	return f.listFiles().length > 0;
    }

    /**
     * 
     * @param folder
     * @return
     * @throws IOException
     * @throws JAXBException
     * @throws XMLStreamException
     */
    private TestVector chooseRandomTestVectorFromFolder(File folder) throws IOException, JAXBException,
	    XMLStreamException {
	TestVector chosenTestVector = null;
	int tries = 0;
	if (folder.exists() && folder.isDirectory()) {
	    do {
		File[] files = folder.listFiles(new GitIgnoreFileFilter());
		Random r = new Random();
		File chosenFile = files[r.nextInt(files.length)];
		chosenTestVector = TestVectorSerializer.read(new FileInputStream(chosenFile));
	    } while (chosenTestVector == null && tries < 1000);
	    if (chosenTestVector == null) {
		throw new IOException("Cannot choose random TestVector from " + folder.getAbsolutePath());
	    }
	} else {
	    throw new IOException("Cannot choose random TestVector from " + folder.getAbsolutePath());
	}
	return chosenTestVector;

    }

    /**
     * 
     * @return
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

}
