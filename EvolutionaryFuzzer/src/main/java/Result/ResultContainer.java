package Result;

import Config.EvolutionaryFuzzerConfig;
import WorkFlowType.WorkflowTraceType;
import WorkFlowType.WorkflowTraceTypeManager;
import de.rub.nds.tlsattacker.tls.config.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBException;
import org.jfree.util.Log;
import Graphs.BranchTrace;

/**
 * This Class manages the BranchTraces and merges newly obtained Workflows with
 * the BranchTrace
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ResultContainer {

    private static final Logger LOG = Logger.getLogger(ResultContainer.class.getName());

    /**
     * Singleton
     * 
     * @return Instance of the ResultContainer
     */
    public static ResultContainer getInstance() {
	return ResultContainerHolder.INSTANCE;
    }

    // BranchTrace with which other Workflows are merged
    private final BranchTrace branch;
    // List of old Results
    private final ArrayList<WorkflowTrace> goodTrace;
    private final Set<WorkflowTraceType> typeSet;
    private boolean serialize = true;
    private final EvolutionaryFuzzerConfig evoConfig;
    private int crashed = 0;
    private int timeout = 0;
    private int executed = 0;

    private ResultContainer() {
	branch = new BranchTrace();
	goodTrace = new ArrayList<>();
	typeSet = new HashSet<>();
	evoConfig = Config.ConfigManager.getInstance().getConfig();

    }

    public boolean isSerialize() {
	return serialize;
    }

    public void setSerialize(boolean serialize) {
	this.serialize = serialize;
    }

    /**
     * Returns a list of WorkflowTraces that found new Branches or Vertices
     * 
     * @return ArrayList of good WorkflowTraces
     */
    public ArrayList<WorkflowTrace> getGoodTraces() {
	return goodTrace;
    }

    /**
     * Merges a Result with the BranchTrace and adds the Result to the
     * ResultList
     * 
     * @param result
     *            Result to be added in the Container
     */
    public void commit(Result result) {
	executed++;
	MergeResult r = null;

	r = branch.merge(result.getBranchTrace());

	if (r != null && (r.getNewBranches() > 0 || r.getNewVertices() > 0)) {
	    LOG.log(Level.FINE, "Found a GoodTrace:{0}", r.toString());
	    // It may be that we dont want to safe good Traces, for example if
	    // we execute already saved Traces
	    if (serialize) {
		File f = new File(evoConfig.getOutputFolder() + "good/" + result.getId());
		try {
		    f.createNewFile();
		    WorkflowTraceSerializer.write(f, result.getExecutedTrace());
		} catch (JAXBException | IOException E) {
		    LOG.log(Level.SEVERE,
			    "Could not write Results to Disk! Does the Fuzzer have the rights to write to {0}",
			    f.getAbsolutePath());
		}
	    }
	    result.getTrace().makeGeneric();
	    goodTrace.add(result.getTrace());

	}
	if (result.hasCrashed()) {
	    crashed++;
	    LOG.log(Level.INFO, "Found a Crash:{0}", r.toString());

	    File f = new File(evoConfig.getOutputFolder() + "crash/" + result.getId());
	    try {
		f.createNewFile();
		WorkflowTraceSerializer.write(f, result.getExecutedTrace());
	    } catch (JAXBException | IOException E) {
		LOG.log(Level.SEVERE,
			"Could not write Results to Disk! Does the Fuzzer have the rights to write to {0}",
			f.getAbsolutePath());
	    }

	}
	if (result.didTimeout()) {
	    timeout++;
	    LOG.log(Level.INFO, "Found a Timeout:{0}", r.toString());

	    File f = new File(evoConfig.getOutputFolder() + "timeout/" + result.getId());
	    try {
		f.createNewFile();
		WorkflowTraceSerializer.write(f, result.getExecutedTrace());
	    } catch (JAXBException | IOException E) {
		LOG.log(Level.SEVERE,
			"Could not write Results to Disk! Does the Fuzzer have the rights to write to {0}",
			f.getAbsolutePath());
	    }

	}
	WorkflowTraceType type = WorkflowTraceTypeManager.generateWorkflowTraceType(result.getExecutedTrace());
	type.clean();
	if (typeSet.add(type) && serialize) {
	    LOG.log(Level.FINE, "Found a new WorkFlowTraceType");
	    LOG.log(Level.FINER, type.toString());
	    File f = new File(evoConfig.getOutputFolder() + "uniqueFlows/" + result.getId());
	    try {
		f.createNewFile();
		WorkflowTraceSerializer.write(f, result.getExecutedTrace());
	    } catch (JAXBException | IOException E) {
		LOG.log(Level.SEVERE,
			"Could not write Results to Disk! Does the Fuzzer have the rights to write to {0}",
			f.getAbsolutePath());
	    }
	}
    }

    public int getExecuted() {
	return executed;
    }

    public BranchTrace getBranch() {
	return branch;
    }

    public int getCrashedCount() {
	return crashed;
    }

    public int getTimeoutCount() {
	return timeout;
    }

    public int getTypeCount() {
	return typeSet.size();
    }

    // Singleton
    private static class ResultContainerHolder {

	private static final ResultContainer INSTANCE = new ResultContainer();

	private ResultContainerHolder() {
	}
    }
}
