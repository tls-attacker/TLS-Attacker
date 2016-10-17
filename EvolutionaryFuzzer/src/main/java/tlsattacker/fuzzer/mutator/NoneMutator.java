package tlsattacker.fuzzer.mutator;

import tlsattacker.fuzzer.certificate.ClientCertificateStructure;
import tlsattacker.fuzzer.mutator.certificate.CertificateMutator;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;
import tlsattacker.fuzzer.mutator.Mutator;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.config.mutator.SimpleMutatorConfig;
import tlsattacker.fuzzer.helper.FuzzingHelper;
import static tlsattacker.fuzzer.helper.FuzzingHelper.executeModifiableVariableModification;
import static tlsattacker.fuzzer.helper.FuzzingHelper.getAllModifiableVariableFieldsRecursively;
import tlsattacker.fuzzer.modification.ChangeClientCertificateModification;
import tlsattacker.fuzzer.modification.ChangeServerCertificateModification;
import tlsattacker.fuzzer.modification.Modification;
import de.rub.nds.tlsattacker.modifiablevariable.util.ModifiableVariableField;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.util.UnoptimizedDeepCopy;
import java.util.List;
import java.util.Random;
import java.util.logging.Logger;
import tlsattacker.fuzzer.result.ResultContainer;
import tlsattacker.fuzzer.testvector.TestVector;
import de.rub.nds.tlsattacker.tls.workflow.action.TLSAction;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.logging.Level;
import javax.imageio.IIOException;
import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import tlsattacker.fuzzer.helper.GitIgnoreFileFilter;
import tlsattacker.fuzzer.testvector.TestVectorSerializer;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class NoneMutator extends Mutator
{

    private static final Logger LOG = Logger.getLogger(NoneMutator.class.getName());

    public static final String optionName = "none";
    private SimpleMutatorConfig simpleConfig;

    /**
     *
     * @param config
     */
    public NoneMutator(EvolutionaryFuzzerConfig evoConfig, CertificateMutator certMutator)
    {
        super(evoConfig, certMutator);
        File f = new File(evoConfig.getMutatorConfigFolder() + "simple.conf");
        if (f.exists())
        {
            simpleConfig = JAXB.unmarshal(f, SimpleMutatorConfig.class);
        }
        else
        {
            simpleConfig = new SimpleMutatorConfig();
            JAXB.marshal(simpleConfig, f);
        }
    }

    private boolean goodVectorsExist()
    {
        File f = new File("data/good/");
        return f.listFiles().length > 0;

    }

    private boolean archiveVectorsExist()
    {
        File f = new File("archive/");
        return f.listFiles().length > 0;
    }

    private TestVector chooseRandomTestVectorFromFolder(File folder) throws IOException, JAXBException,
                                                                            XMLStreamException
    {
        TestVector chosenTestVector = null;
        int tries = 0;
        if (folder.exists() && folder.isDirectory())
        {
            do
            {
                File[] files = folder.listFiles(new GitIgnoreFileFilter());
                Random r = new Random();
                File chosenFile = files[r.nextInt(files.length)];
                chosenTestVector = TestVectorSerializer.read(new FileInputStream(chosenFile));
            }
            while (chosenTestVector == null && tries < 1000);
            if (chosenTestVector == null)
            {
                throw new IOException("Cannot choose random TestVector from " + folder.getAbsolutePath());
            }
        }
        else
        {
            throw new IOException("Cannot choose random TestVector from " + folder.getAbsolutePath());
        }
        return chosenTestVector;

    }

    /**
     *
     * @return
     */
    @Override
    public TestVector getNewMutation()
    {
        Random r = new Random();
        // chose a random trace from the list
        TestVector tempVector = null;
        WorkflowTrace trace = null;

        if (goodVectorsExist())
        {
            try
            {
                tempVector = chooseRandomTestVectorFromFolder(new File("data/good/"));
            }
            catch (IOException | JAXBException | XMLStreamException ex)
            {
                LOG.log(Level.SEVERE, "Could not read good TestVector", ex);
            }
        }
        else if (archiveVectorsExist())
        {
            try
            {
                tempVector = chooseRandomTestVectorFromFolder(new File("archive/"));
            }
            catch (IOException | JAXBException | XMLStreamException ex)
            {
                LOG.log(Level.SEVERE, "Could not read archive TestVector", ex);
            }
        }
        if (tempVector == null)
        {
            tempVector = new TestVector(new WorkflowTrace(), certMutator.getServerCertificateStructure(),
                    certMutator.getClientCertificateStructure(), config.getActionExecutorConfig()
                    .getRandomExecutorType(), null);
        }
        tempVector.getTrace().reset();
        tempVector.getTrace().makeGeneric();
        return tempVector;

    }

}
