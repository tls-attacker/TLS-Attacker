package Mutator;

import Mutator.Certificate.CertificateMutator;
import TestVector.ServerCertificateKeypair;
import Mutator.Mutator;
import Config.EvolutionaryFuzzerConfig;
import Config.Mutator.SimpleMutatorConfig;
import Helper.FuzzingHelper;
import static Helper.FuzzingHelper.executeModifiableVariableModification;
import static Helper.FuzzingHelper.getAllModifiableVariableFieldsRecursively;
import Helper.XMLSerializer;
import Modification.ChangeServerCertificateModification;
import Modification.Modification;
import de.rub.nds.tlsattacker.modifiablevariable.util.ModifiableVariableField;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.util.UnoptimizedDeepCopy;
import java.util.List;
import java.util.Random;
import java.util.logging.Logger;
import Result.ResultContainer;
import TestVector.TestVector;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.logging.Level;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class SimpleMutator extends Mutator {

    private static final Logger LOG = Logger.getLogger(SimpleMutator.class.getName());

    // private final Node<WorkflowTrace> tree;
    private int goodIndex = 0;
    private SimpleMutatorConfig config;

    /**
     * 
     * @param config
     */
    public SimpleMutator(EvolutionaryFuzzerConfig evoConfig, CertificateMutator certMutator) {
	super(evoConfig, certMutator);
	File f = new File(evoConfig.getConfigFolder() + "mutator/simple.conf");
	if (f.exists()) {
	    try {
		config = (SimpleMutatorConfig) XMLSerializer.read(f);
	    } catch (FileNotFoundException ex) {
		Logger.getLogger(SimpleMutator.class.getName()).log(Level.SEVERE, null, ex);
	    }
	} else {
	    config = new SimpleMutatorConfig();
	    try {
		XMLSerializer.write(config, f);
	    } catch (IOException ex) {
		Logger.getLogger(SimpleMutator.class.getName()).log(Level.SEVERE, null, ex);
	    }
	}
    }

    /**
     * 
     * @return
     */
    @Override
    public TestVector getNewMutation() {
	Random r = new Random();
	// chose a random trace from the list
	TestVector tempVector;
	WorkflowTrace trace = null;
	ServerCertificateKeypair keyCertPair;
	TestVector newTestVector;
	boolean modified = false;
	do {
	    if (ResultContainer.getInstance().getGoodVectors().isEmpty()) {
		tempVector = new TestVector(new WorkflowTrace(), certMutator.getServerCertificateKeypair(), null);
		ResultContainer.getInstance().getGoodVectors().add(tempVector);
		modified = true;
	    } else {
		// Choose a random Trace to modify
		tempVector = ResultContainer.getInstance().getGoodVectors()
			.get(r.nextInt(ResultContainer.getInstance().getGoodVectors().size()));
	    }
	    keyCertPair = tempVector.getKeyCertPair();
	    trace = (WorkflowTrace) UnoptimizedDeepCopy.copy(tempVector.getTrace());
	    Modification modification = null;
	    if (r.nextInt(100) <= config.getChangeServerCert()) {
		keyCertPair = certMutator.getServerCertificateKeypair();
		modification = new ChangeServerCertificateModification(keyCertPair);
		modified = true;
	    }
	    newTestVector = new TestVector(trace, keyCertPair, tempVector);
	    if (modification != null) {
		newTestVector.addModification(modification);
	    }
	    // perhaps add a message
	    if (trace.getProtocolMessages().isEmpty() || r.nextInt(100) < config.getAddMessagePercentage()) {
		newTestVector.addModification(FuzzingHelper.addRandomMessage(trace));
		modified = true;
	    }
	    // perhaps remove a message
	    if (r.nextInt(100) <= config.getRemoveMessagePercentage()) {
		newTestVector.addModification(FuzzingHelper.removeRandomMessage(trace));
		modified = true;
	    }
	    if (trace.getProtocolMessages().isEmpty()) {
		newTestVector.addModification(FuzzingHelper.addRandomMessage(trace));
		modified = true;
	    }
	    // perhaps add records
	    if (r.nextInt(100) <= config.getAddRecordPercentage()) {
		newTestVector.addModification(FuzzingHelper.addRecordAtRandom(trace, ConnectionEnd.CLIENT));
		modified = true;
	    }
	    // Modify a random field:
	    if (r.nextInt(100) <= config.getModifyVariablePercentage()) {
		List<ModifiableVariableField> variableList = getAllModifiableVariableFieldsRecursively(trace,
			ConnectionEnd.CLIENT);
		// LOG.log(Level.INFO, ""+trace.getProtocolMessages().size());
		if (variableList.size() > 0) {
		    ModifiableVariableField field = variableList.get(r.nextInt(variableList.size()));
		    // String currentFieldName = field.getField().getName();
		    // String currentMessageName =
		    // field.getObject().getClass().getSimpleName();
		    // LOG.log(Level.INFO, "Fieldname:{0} Message:{1}", new
		    // Object[]{currentFieldName, currentMessageName});
		    newTestVector.addModification(executeModifiableVariableModification(
			    (ModifiableVariableHolder) field.getObject(), field.getField()));
		    modified = true;
		}
	    }
	    if (r.nextInt(100) <= config.getDuplicateMessagePercentage()) {
		newTestVector
			.addModification(FuzzingHelper.duplicateRandomProtocolMessage(trace, ConnectionEnd.CLIENT));
		modified = true;
	    }
	} while (!modified || r.nextInt(100) <= config.getMultipleModifications());
	return newTestVector;

    }

}
