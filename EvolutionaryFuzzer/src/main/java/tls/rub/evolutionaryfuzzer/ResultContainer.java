/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tls.rub.evolutionaryfuzzer;

import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.logging.Logger;
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
        try
        {
            MergeResult r = branch.merge(result.getEdges());
            if (r.getNewBranches() > 0 || r.getNewVertices() > 0)
            {
                goodTrace.add(result.getTrace());
                //TODO LOG TRACE
                //System.out.println("***********************************************************************");
                System.out.println(r);
                //System.out.println("***********************************************************************");
            }
            if(result.isHasCrashed())
            {
                System.out.println("CRASHED");
            }
            if(result.isDidTimeout())
            {
                System.out.println("TIMEOUT");
            }
        }
        catch (FileNotFoundException ex)
        {
            //TODO debug
            System.out.println("Could not find File provided in Result, skipping");
        }
        catch (IOException ex)
        {
            //TODO debug
            System.out.println("Could not read File provided in Result, skipping");

        }

    }
    private static final Logger LOG = Logger.getLogger(ResultContainer.class.getName());
}
