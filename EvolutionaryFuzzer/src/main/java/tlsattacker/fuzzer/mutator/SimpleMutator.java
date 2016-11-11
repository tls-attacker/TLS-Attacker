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
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.util.List;
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
 * A simple Mutator implementations that applies modifications to random good
 * TestVectors as specified in a configuration file.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class SimpleMutator extends Mutator {

    /**
     * The name of the Mutator when referred by command line
     */
    public static final String optionName = "simple";

    /**
     * The config to use
     */
    private final SimpleMutatorConfig simpleConfig;

    public SimpleMutator(EvolutionaryFuzzerConfig evoConfig, CertificateMutator certMutator) {
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
     * Chooses a random TestVecotr and applies different Modification to it as
     * specified in the configuration file. There is a change the a single
     * TestVector is modified multiple times in a row.
     * 
     * @return Newly generated TestVector
     */
    @Override
    public TestVector getNewMutation() {
        Random r = new Random();
        // chose a random trace from the list
        TestVector tempVector = null;
        WorkflowTrace trace = null;

        boolean modified = false;
        do {
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
            tempVector.clearModifications();
            Modification modification = null;
            trace = tempVector.getTrace();
            if (r.nextInt(100) <= simpleConfig.getChangeServerCert()) {
                ServerCertificateStructure serverKeyCertPair = certMutator.getServerCertificateStructure();
                modification = new ChangeServerCertificateModification(serverKeyCertPair);
                tempVector.setServerKeyCert(serverKeyCertPair);
                modified = true;
            }
            if (r.nextInt(100) <= simpleConfig.getChangeClientCertPercentage()) {
                ClientCertificateStructure clientKeyCertPair = certMutator.getClientCertificateStructure();
                modification = new ChangeClientCertificateModification(clientKeyCertPair);
                tempVector.setClientKeyCert(clientKeyCertPair);
                modified = true;
            }
            if (modification != null) {
                tempVector.addModification(modification);
            }
            if (r.nextInt(100) < simpleConfig.getAddContextActionPercentage()) {
                tempVector.addModification(FuzzingHelper.addContextAction(trace, certMutator));
                modified = true;
            }
            if (r.nextInt(100) < simpleConfig.getAddExtensionPercentage()) {
                tempVector.addModification(FuzzingHelper.addExtensionMessage(trace));
                modified = true;
            }
            // perhaps add a flight
            if (trace.getTLSActions().isEmpty() || r.nextInt(100) < simpleConfig.getAddFlightPercentage()) {
                tempVector.addModification(FuzzingHelper.addMessageFlight(trace));
                modified = true;
            }
            if (r.nextInt(100) < simpleConfig.getAddMessagePercentage()) {
                tempVector.addModification(FuzzingHelper.addRandomMessage(trace));
                modified = true;
            }
            // perhaps remove a message
            if (r.nextInt(100) <= simpleConfig.getRemoveMessagePercentage()) {
                tempVector.addModification(FuzzingHelper.removeRandomMessage(trace));
                modified = true;
            }
            // perhaps toggle Encryption
            if (r.nextInt(100) <= simpleConfig.getAddToggleEncrytionPercentage()) {
                tempVector.addModification(FuzzingHelper.addToggleEncrytionActionModification(trace));
                modified = true;
            }
            // perhaps add records
            if (r.nextInt(100) <= simpleConfig.getAddRecordPercentage()) {
                tempVector.addModification(FuzzingHelper.addRecordAtRandom(trace));
                modified = true;
            }
            // Modify a random field:
            if (r.nextInt(100) <= simpleConfig.getModifyVariablePercentage()) {
                List<ModifiableVariableField> variableList = getAllModifiableVariableFieldsRecursively(trace);
                // LOG.log(Level.INFO, ""+trace.getProtocolMessages().size());
                if (variableList.size() > 0) {
                    ModifiableVariableField field = variableList.get(r.nextInt(variableList.size()));
                    // String currentFieldName = field.getField().getName();
                    // String currentMessageName =
                    // field.getObject().getClass().getSimpleName();
                    // LOG.log(Level.INFO, "Fieldname:{0} Message:{1}", new
                    // Object[]{currentFieldName, currentMessageName});
                    tempVector.addModification(executeModifiableVariableModification(
                            (ModifiableVariableHolder) field.getObject(), field.getField()));
                    modified = true;
                }
            }
            if (r.nextInt(100) <= simpleConfig.getDuplicateMessagePercentage()) {
                tempVector.addModification(FuzzingHelper.duplicateRandomProtocolMessage(trace));
                modified = true;
            }
        } while (!modified || r.nextInt(100) <= simpleConfig.getMultipleModifications());
        return tempVector;
    }

    private static final Logger LOG = Logger.getLogger(SimpleMutator.class.getName());
}
