/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tls.rub.evolutionaryfuzzer;

import de.rub.nds.tlsattacker.tls.config.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBException;
import tls.branchtree.BranchTrace;
import tls.branchtree.MergeResult;

/**
 * This Class manages the BranchTraces and merges newly obtained Workflows with
 * the BranchTrace
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ResultContainer
{

    //BranchTrace with which other Workflows are merged
    private final BranchTrace branch;
    //List of old Results
    private final ArrayList<Result> results;
    private final ArrayList<WorkflowTrace> goodTrace;

    private ResultContainer()
    {
        branch = new BranchTrace();
        results = new ArrayList<>();
        goodTrace = new ArrayList<>();
    }

    /**
     * Singleton
     *
     * @return Instance of the ResultContainer
     */
    public static ResultContainer getInstance()
    {
        return ResultContainerHolder.INSTANCE;
    }

    //Singleton
    private static class ResultContainerHolder
    {

        private static final ResultContainer INSTANCE = new ResultContainer();

        private ResultContainerHolder()
        {
        }
    }

    /**
     * Returns a list of WorkflowTraces that found new Branches or Vertices
     *
     * @return ArrayList of good WorkflowTraces
     */
    public ArrayList<WorkflowTrace> getGoodTraces()
    {
        return goodTrace;
    }

    /**
     * Merges a Result with the BranchTrace and adds the Result to the
     * ResultList
     *
     * @param result Result to be added in the Container
     */
    public void commit(Result result)
    {
        results.add(result);
        MergeResult r = null;
        try
        {
            r = branch.merge(result.getEdges());

        }
        catch (FileNotFoundException ex)
        {
            LOG.log(Level.SEVERE, "Received a Result Object wich Points to a non-existant File! Was the File deleted at Runtime? Skipping Result");
            return;
        }
        catch (IOException ex)
        {
            LOG.log(Level.SEVERE, "Received a Result Object wich Points to a File we cant Read! Does the Fuzzer have the rights to read the Files provided by the Agent? Skipping Result");
            return;
        }
        if (r != null && (r.getNewBranches() > 0 || r.getNewVertices() > 0))
        {
            LOG.log(Level.INFO, "Found a GoodTrace:" + r.toString());
            goodTrace.add(result.getTrace());
            File f = new File("good/" + result.getId());

            try
            {
                f.createNewFile();
                WorkflowTraceSerializer.write(f, result.getExecutedTrace());
            }
            catch (JAXBException | IOException E)
            {
                LOG.log(Level.SEVERE, "Could not write Results to Disk! Does the Fuzzer have the rights to write to " + f.getAbsolutePath());
            }
        }
        if (result.hasCrashed())
        {
            LOG.log(Level.INFO, "Found a Crash:" + r.toString());
            File f = new File("crashed/" + result.getId());

            try
            {
                f.createNewFile();
                WorkflowTraceSerializer.write(f, result.getExecutedTrace());
            }
            catch (JAXBException | IOException E)
            {
                LOG.log(Level.SEVERE, "Could not write Results to Disk! Does the Fuzzer have the rights to write to " + f.getAbsolutePath());
            }
        }
        if (result.didTimeout())
        {

            LOG.log(Level.INFO, "Found a Timeout:" + r.toString());
            File f = new File("timeout/" + result.getId());

            try
            {
                f.createNewFile();
                WorkflowTraceSerializer.write(f, result.getExecutedTrace());
            }
            catch (JAXBException | IOException E)
            {
                LOG.log(Level.SEVERE, "Could not write Results to Disk! Does the Fuzzer have the rights to write to " + f.getAbsolutePath());
            }
        }

    }
    private static final Logger LOG = Logger.getLogger(ResultContainer.class.getName());
}
