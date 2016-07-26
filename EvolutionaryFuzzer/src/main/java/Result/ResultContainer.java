package Result;

import Analyzer.Analyzer;
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

    // List of old Results
    private final ArrayList<WorkflowTrace> goodTrace;
    private final Set<WorkflowTraceType> typeSet;
    private final EvolutionaryFuzzerConfig evoConfig;
    private int executed = 0;
    private Analyzer analyzer;

    private ResultContainer() {
	goodTrace = new ArrayList<>();
	typeSet = new HashSet<>();
	evoConfig = Config.ConfigManager.getInstance().getConfig();
	analyzer = new Analyzer(evoConfig);
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
	analyzer.analyze(result);
	WorkflowTraceType type = WorkflowTraceTypeManager.generateWorkflowTraceType(result.getExecutedTrace());
	type.clean();
	if (typeSet.add(type) && evoConfig.isSerialize()) {
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

    public int getTypeCount() {
	return typeSet.size();
    }

    public void addGoodTrace(WorkflowTrace trace) {
	goodTrace.add(trace);
    }

    public Analyzer getAnalyzer() {
	return analyzer;
    }

    // Singleton
    private static class ResultContainerHolder {

	private static final ResultContainer INSTANCE = new ResultContainer();

	private ResultContainerHolder() {
	}
    }
}
