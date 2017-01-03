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
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import tlsattacker.fuzzer.result.TestVectorResult;

/**
 * This class runs an infitie Loop and analyzes all Results passed to it
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class AnalyzerThread extends Thread {

    static final Logger LOGGER = LogManager.getLogger(AnalyzerThread.class);

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
                        } catch (InterruptedException | ExecutionException ex) {
                            LOGGER.error("Could not retrieve Result from finished Future", ex);
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
                    LOGGER.error(ex.getLocalizedMessage(), ex);
                }
            }
        }
    }

}
