/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tls.rub.evolutionaryfuzzer;

import Config.EvolutionaryFuzzerConfig;
import de.rub.nds.tlsattacker.tls.config.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This ThreadPool manages the Threads for the different Executors and is
 * responsible for the continious exectution of new Fuzzingvectors.
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ExecutorThreadPool implements Runnable {

    //Number of Threads which execute FuzzingVectors 
    private final int poolSize;
    //
    private final ExecutorService executor;
    //The Mutator used by the ExecutorPool to fetch new Tasks
    private final Mutator mutator;
    //The Executor thread pool will continuasly fetch and execute new Tasks while this is false
    private boolean stopped = false;
    //Counts the number of executed Tasks for statisticall purposes.
    private long runs = 0;
    //List of Workflowtraces that should be executed before we start generating new Workflows
    private final List<WorkflowTrace> list;
    //The Config the ExecutorThreadPool uses
    private EvolutionaryFuzzerConfig config;

    /**
     * Constructor for the ExecutorThreadPool
     *
     * @param poolSize Number of Threads the pool Manages
     * @param mutator Mutator which is used for the Generation of new
     * FuzzingVectors.
     */
    public ExecutorThreadPool(int poolSize, Mutator mutator, EvolutionaryFuzzerConfig config) {
        this.config = config;
        this.poolSize = poolSize;
        this.mutator = mutator;
        File f = new File(config.getOutputFolder() + "good/");
        executor = Executors.newFixedThreadPool(poolSize);

        LOG.log(Level.INFO, "Reading good Traces in:");

        list = WorkflowTraceSerializer.readFolder(f);
        f = new File(config.getOutputFolder() + "uniqueFlows/");
        
        list.addAll(WorkflowTraceSerializer.readFolder(f));
        LOG.log(Level.INFO, "Loaded old good Traces:{0}", list.size());
    }

    /**
     * Returns the Number of executed FuzzingVectors
     *
     * @return Number of executed FuzzingVectors
     */
    public long getRuns() {
        return runs;
    }

    /**
     * Starts the Thread which manages the other Threads
     */
    @Override
    public void run() {
        //Dont save old results
        ResultContainer.getInstance().setSerialize(false);
        for (int i = 0; i < list.size(); i++) {
            if (!stopped) {
                TLSServer server = ServerManager.getInstance().getFreeServer();
                Runnable worker = new TLSExecutor(list.get(i), server, new BasicAFLAgent());
                executor.execute(worker);
            } else {
                i--;
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ex) {
                    Logger.getLogger(ExecutorThreadPool.class.getName()).log(Level.SEVERE, "Thread interruiped while the ThreadPool is paused.", ex);
                }
            }
        }
        //Save new results
        ResultContainer.getInstance().setSerialize(true);
        while (true) {
            if (!stopped) {
                TLSServer server = ServerManager.getInstance().getFreeServer();

                Runnable worker = new TLSExecutor(mutator.getNewMutation(), server, new BasicAFLAgent());
                executor.execute(worker);
                runs++;

            } else {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ex) {
                    Logger.getLogger(ExecutorThreadPool.class.getName()).log(Level.SEVERE, "Thread interruiped while the ThreadPool is paused.", ex);
                }
            }
        }
        /*
         executor.shutdown();
         while (!executor.isTerminated()) {
         }
         System.out.println('ExecutorThread Pool Shutdown');
         */
    }

    /**
     * Returns if the ThreadPool is currently stopped.
     *
     * @return if the ThreadPool is currently stopped
     */
    public synchronized boolean isStopped() {
        return stopped;
    }

    /**
     * Starts of stops the Threadpool
     *
     * @param stopped
     */
    public synchronized void setStopped(boolean stopped) {
        this.stopped = stopped;
    }
    private static final Logger LOG = Logger.getLogger(ExecutorThreadPool.class.getName());
}
