/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer;

import java.util.LinkedList;
import java.util.List;
import java.util.Stack;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.logging.Level;
import java.util.logging.Logger;
import tlsattacker.fuzzer.result.TestVectorResult;

/**
 * This class runs an infitie Loop and analyzes all Results passed to it
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class AnalyzerThread extends Thread {

    /**
     * The analyzer used to analyze the Results
     */
    private final Analyzer analyzer;

    /**
     * The list of Results to analyze, used as a queque
     */
    private final LinkedList<Future<TestVectorResult>> workList;

    public AnalyzerThread(Analyzer analyzer) {
        this.analyzer = analyzer;
        workList = new LinkedList<>();
    }

    /**
     * Adds a result to the worklist
     *
     * @param result
     *            AgentResult to add to the worklist
     */
    public synchronized void addToAnalyzeQueque(Future<TestVectorResult> result) {
        workList.add(result);
        notifyAll();
    }

    @Override
    public void run() {
        while (true) {
            if (!workList.isEmpty()) {
                synchronized (this) {
                    Future future = workList.pop();
                    if (future.isDone()) {
                        TestVectorResult result = null;
                        try {
                            result = (TestVectorResult) future.get();
                        } catch (InterruptedException ex) {
                            LOG.log(Level.SEVERE, "Could not retrieve Result from finished Future", ex);
                        } catch (ExecutionException ex) {
                            LOG.log(Level.SEVERE, "Could not retrieve Result from finished Future", ex);
                        }
                        if (result != null) {
                            analyzer.analyze(result);
                        }
                    } else {
                        workList.addLast(future);
                    }
                }
            } else {
                try {
                    synchronized (this) {
                        wait();
                    }
                } catch (InterruptedException ex) {
                    Logger.getLogger(AnalyzerThread.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
    }

    private static final Logger LOG = Logger.getLogger(AnalyzerThread.class.getName());

}
