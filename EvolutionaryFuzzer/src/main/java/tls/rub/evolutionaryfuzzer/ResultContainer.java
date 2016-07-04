package tls.rub.evolutionaryfuzzer;

import Config.EvolutionaryFuzzerConfig;
import WorkFlowType.WorkFlowTraceType;
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
import tls.branchtree.BranchTrace;
import tls.branchtree.MergeResult;

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

    //BranchTrace with which other Workflows are merged
    private final BranchTrace branch;
    //List of old Results
    private final ArrayList<Result> results;
    private final ArrayList<WorkflowTrace> goodTrace;
    private final Set<WorkFlowTraceType> set;
    private boolean serialize = true;
    private EvolutionaryFuzzerConfig evoConfig;
    public boolean isSerialize() {
        return serialize;
    }

    public void setSerialize(boolean serialize) {
        this.serialize = serialize;
    }

    private ResultContainer() {
        branch = new BranchTrace();
        results = new ArrayList<>();
        goodTrace = new ArrayList<>();
        set = new HashSet<>();
        evoConfig = Config.ConfigManager.getInstance().getConfig();
        
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
     * @param result Result to be added in the Container
     */
    public void commit(Result result) {
        results.add(result);
        MergeResult r = null;
        try {
            r = branch.merge(result.getEdges());

        } catch (FileNotFoundException ex) {
            LOG.log(Level.SEVERE, "Received a Result Object wich Points to a non-existant File! Was the File deleted at Runtime? Skipping Result");
            return;
        } catch (IOException ex) {
            LOG.log(Level.SEVERE, "Received a Result Object wich Points to a File we cant Read! Does the Fuzzer have the rights to read the Files provided by the Agent? Skipping Result");
            return;
        }
        if (r != null && (r.getNewBranches() > 0 || r.getNewVertices() > 0)) {
            LOG.log(Level.INFO, "Found a GoodTrace:{0}", r.toString());
            goodTrace.add(result.getTrace());
            //It may be that we dont want to safe good Traces, for example if we execute already saved Traces 
            if (serialize) {
                File f = new File(evoConfig.getOutputFolder()+"good/" + result.getId());
                try {
                    f.createNewFile();
                    WorkflowTraceSerializer.write(f, result.getExecutedTrace());
                } catch (JAXBException | IOException E) {
                    LOG.log(Level.SEVERE, "Could not write Results to Disk! Does the Fuzzer have the rights to write to {0}", f.getAbsolutePath());
                }
            }
        }
        if (result.hasCrashed()) {
            LOG.log(Level.INFO, "Found a Crash:{0}", r.toString());
            if (serialize) {
                File f = new File(evoConfig.getOutputFolder()+"crashed/" + result.getId());
                try {
                    f.createNewFile();
                    WorkflowTraceSerializer.write(f, result.getExecutedTrace());
                } catch (JAXBException | IOException E) {
                    LOG.log(Level.SEVERE, "Could not write Results to Disk! Does the Fuzzer have the rights to write to {0}", f.getAbsolutePath());
                }
            }
        }
        if (result.didTimeout()) {
            LOG.log(Level.INFO, "Found a Timeout:{0}", r.toString());
            if (serialize) {
                File f = new File(evoConfig.getOutputFolder()+"timeout/" + result.getId());
                try {
                    f.createNewFile();
                    WorkflowTraceSerializer.write(f, result.getExecutedTrace());
                } catch (JAXBException | IOException E) {
                    LOG.log(Level.SEVERE, "Could not write Results to Disk! Does the Fuzzer have the rights to write to {0}", f.getAbsolutePath());
                }
            }
        }
        WorkFlowTraceType type = WorkflowTraceTypeManager.generateWorkflowTraceType(result.getExecutedTrace());
        if (set.add(type) && serialize) {
            LOG.log(Level.INFO, "Found a new WorkFlowTraceType");
            LOG.log(Level.FINER, type.toString());
            File f = new File(evoConfig.getOutputFolder()+"uniqueFlows/" + result.getId());
            try {
                f.createNewFile();
                WorkflowTraceSerializer.write(f, result.getExecutedTrace());
            } catch (JAXBException | IOException E) {
                LOG.log(Level.SEVERE, "Could not write Results to Disk! Does the Fuzzer have the rights to write to {0}", f.getAbsolutePath());
            }
        }
    }

    //Singleton
    private static class ResultContainerHolder {

        private static final ResultContainer INSTANCE = new ResultContainer();

        private ResultContainerHolder() {
        }
    }
}
