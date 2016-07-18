package Mutator;

import Mutator.Mutator;
import Config.EvolutionaryFuzzerConfig;
import Helper.FuzzingHelper;
import static Helper.FuzzingHelper.executeModifiableVariableModification;
import static Helper.FuzzingHelper.getAllModifiableVariableFieldsRecursively;
import de.rub.nds.tlsattacker.modifiablevariable.util.ModifiableVariableField;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.util.UnoptimizedDeepCopy;
import java.util.List;
import java.util.Random;
import java.util.logging.Logger;
import Result.ResultContainer;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class SimpleMutator extends Mutator {

    private static final Logger LOG = Logger.getLogger(SimpleMutator.class.getName());

    // private final Node<WorkflowTrace> tree;
    private final TlsContext context;
    private int goodIndex = 0;

    /**
     * 
     * @param context
     * @param config
     */
    public SimpleMutator(TlsContext context, EvolutionaryFuzzerConfig config) {
	super(config);

	this.context = context;

    }

    /**
     * 
     * @return
     */
    @Override
    public WorkflowTrace getNewMutation() {
	Random r = new Random();
	// chose a random trace from the list
	WorkflowTrace tempTrace;
	WorkflowTrace trace = null;
	boolean modified = false;
	do {
	    if (ResultContainer.getInstance().getGoodTraces().isEmpty()) {
		tempTrace = new WorkflowTrace();
		ResultContainer.getInstance().getGoodTraces().add(tempTrace);
		modified = true;
	    } else {
		// Choose a random Trace to modify
		tempTrace = ResultContainer.getInstance().getGoodTraces()
			.get(r.nextInt(ResultContainer.getInstance().getGoodTraces().size()));
	    }

	    trace = (WorkflowTrace) UnoptimizedDeepCopy.copy(tempTrace);
	    // perhaps add a message
	    if (trace.getProtocolMessages().isEmpty() || r.nextInt(100) < config.getAddMessagePercentage()) {
		FuzzingHelper.addRandomMessage(trace);
		modified = true;
	    }
	    // perhaps remove a message
	    if (r.nextInt(100) <= config.getRemoveMessagePercentage()) {
		FuzzingHelper.removeRandomMessage(trace);
		modified = true;
	    }
	    if (trace.getProtocolMessages().isEmpty()) {
		FuzzingHelper.addRandomMessage(trace);
		modified = true;
	    }
	    // perhaps add records
	    if (r.nextInt(100) <= config.getAddRecordPercentage()) {
		FuzzingHelper.addRecordsAtRandom(trace, ConnectionEnd.CLIENT);
		modified = true;
	    }
	    // Modify a random field:
	    if (r.nextInt(100) <= config.getModifyVariablePercentage()) {
		List<ModifiableVariableField> variableList = getAllModifiableVariableFieldsRecursively(trace,
			ConnectionEnd.CLIENT);
		// LOG.log(Level.INFO, ""+trace.getProtocolMessages().size());
		if (variableList.size() > 0) {
		    ModifiableVariableField field = variableList.get(r.nextInt(variableList.size()));
		    String currentFieldName = field.getField().getName();
		    String currentMessageName = field.getObject().getClass().getSimpleName();
		    // LOG.log(Level.INFO, "Fieldname:{0} Message:{1}", new
		    // Object[]{currentFieldName, currentMessageName});
		    executeModifiableVariableModification((ModifiableVariableHolder) field.getObject(),
			    field.getField());
		    modified = true;
		}
	    }
	    if (r.nextInt(100) <= config.getDuplicateMessagePercentage()) {
		FuzzingHelper.duplicateRandomProtocolMessage(trace, ConnectionEnd.CLIENT);
		modified = true;
	    }
	} while (!modified);
	return trace;

    }

}
