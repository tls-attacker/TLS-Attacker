/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.mutator;

import tlsattacker.fuzzer.certificate.ClientCertificateStructure;
import tlsattacker.fuzzer.mutator.certificate.CertificateMutator;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.config.mutator.SimpleMutatorConfig;
import tlsattacker.fuzzer.helper.FuzzingHelper;
import tlsattacker.fuzzer.modification.ChangeClientCertificateModification;
import tlsattacker.fuzzer.modification.ChangeServerCertificateModification;
import tlsattacker.fuzzer.modification.Modification;
import de.rub.nds.tlsattacker.modifiablevariable.util.ModifiableVariableField;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.util.List;
import java.util.Random;
import tlsattacker.fuzzer.testvector.TestVector;
import java.io.File;
import java.io.IOException;
import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;

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

    /**
     * The fuzzing helper that should be used
     */
    private FuzzingHelper fuzzingHelper;

    public SimpleMutator(EvolutionaryFuzzerConfig evoConfig, CertificateMutator certMutator) {
        super(evoConfig, certMutator);
        fuzzingHelper = new FuzzingHelper();
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
                    LOGGER.error("Could not read good TestVector", ex);
                }
            } else if (archiveVectorsExist()) {
                try {
                    tempVector = chooseRandomTestVectorFromFolder(new File("archive/"));
                } catch (IOException | JAXBException | XMLStreamException ex) {
                    LOGGER.error("Could not read archive TestVector", ex);
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
                tempVector.addModification(fuzzingHelper.addContextAction(trace, certMutator));
                modified = true;
            }
            if (r.nextInt(100) < simpleConfig.getAddExtensionPercentage()) {
                tempVector.addModification(fuzzingHelper.addExtensionMessage(trace));
                modified = true;
            }
            // perhaps add a flight
            if (trace.getTLSActions().isEmpty() || r.nextInt(100) < simpleConfig.getAddFlightPercentage()) {
                tempVector.addModification(fuzzingHelper.addMessageFlight(trace));
                modified = true;
            }
            if (r.nextInt(100) < simpleConfig.getAddMessagePercentage()) {
                tempVector.addModification(fuzzingHelper.addRandomMessage(trace));
                modified = true;
            }
            // perhaps remove a message
            if (r.nextInt(100) <= simpleConfig.getRemoveMessagePercentage()) {
                tempVector.addModification(fuzzingHelper.removeRandomMessage(trace));
                modified = true;
            }
            // perhaps toggle Encryption
            if (r.nextInt(100) <= simpleConfig.getAddToggleEncrytionPercentage()) {
                tempVector.addModification(fuzzingHelper.addToggleEncrytionActionModification(trace));
                modified = true;
            }
            // perhaps add records
            if (r.nextInt(100) <= simpleConfig.getAddRecordPercentage()) {
                tempVector.addModification(fuzzingHelper.addRecordAtRandom(trace));
                modified = true;
            }
            // Modify a random field:
            if (r.nextInt(100) <= simpleConfig.getModifyVariablePercentage()) {
                List<ModifiableVariableField> variableList = fuzzingHelper
                        .getAllModifiableVariableFieldsRecursively(trace);
                // LOGGER.info(""+trace.getProtocolMessages().size());
                if (variableList.size() > 0) {
                    ModifiableVariableField field = variableList.get(r.nextInt(variableList.size()));
                    // String currentFieldName = field.getField().getName();
                    // String currentMessageName =
                    // field.getObject().getClass().getSimpleName();
                    // LOGGER.info("Fieldname:{0} Message:{1}", new
                    // Object[]{currentFieldName, currentMessageName});
                    tempVector.addModification(fuzzingHelper.executeModifiableVariableModification(
                            (ModifiableVariableHolder) field.getObject(), field.getField()));
                    modified = true;
                }
            }
            if (r.nextInt(100) <= simpleConfig.getDuplicateMessagePercentage()) {
                tempVector.addModification(fuzzingHelper.duplicateRandomProtocolMessage(trace));
                modified = true;
            }
        } while (!modified || r.nextInt(100) <= simpleConfig.getMultipleModifications());
        return tempVector;
    }

}
