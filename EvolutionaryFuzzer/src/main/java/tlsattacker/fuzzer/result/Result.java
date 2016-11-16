/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.result;

import java.util.logging.Logger;
import tlsattacker.fuzzer.graphs.BranchTrace;
import tlsattacker.fuzzer.testvector.TestVector;

/**
 * This class summarizes a the Results of FuzzingVector. It contains information
 * about a potential timeout, or crash. It containts information about the Time
 * the Vector took to Execute, the Controlflow Branches that were executed by
 * the Vector.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class Result {

    /**
     * If the Implementation has Crashed
     */
    private final boolean hasCrashed;

    /**
     * If the Implementation did Timeout
     */
    private boolean didTimeout;

    /**
     * The Unixtime @ which the Vector started executing
     */
    private final long startTime;

    /**
     * The Unixtime @ which the Vector finished executing
     */
    private final long stopTime;

    /**
     * The instrumentation result
     */
    private final BranchTrace branchTrace;

    /**
     * The TestVector that was executed
     */
    private final TestVector vector;

    /**
     * Each Result get an id for easier referencing
     */
    private final String id;

    /**
     * If the Result is considered a good Trace, eg. if it found new Codepaths
     * false means no
     * true means yes
     * and null means, we dont know yet
     */
    private Boolean goodTrace = null;

    /**
     * 
     * @param hasCrashed
     * @param didTimeout
     * @param startTime
     * @param stopTime
     * @param branchTrace
     * @param vector
     * @param id
     */
    public Result(boolean hasCrashed, boolean didTimeout, long startTime, long stopTime, BranchTrace branchTrace,
            TestVector vector, String id) {
        this.hasCrashed = hasCrashed;
        this.didTimeout = didTimeout;
        this.startTime = startTime;
        this.stopTime = stopTime;
        this.branchTrace = branchTrace;
        this.vector = vector;
        this.id = id;
    }

    public Boolean isGoodTrace() {
        return goodTrace;
    }

    public void setGoodTrace(Boolean wasGoodTrace) {
        this.goodTrace = wasGoodTrace;
    }

    public void setDidTimeout(boolean didTimeout) {
        this.didTimeout = didTimeout;
    }

    public String getId() {
        return id;
    }

    public boolean hasCrashed() {
        return hasCrashed;
    }

    public boolean didTimeout() {
        return didTimeout;
    }

    public long getStartTime() {
        return startTime;
    }

    public long getStopTime() {
        return stopTime;
    }

    public BranchTrace getBranchTrace() {
        return branchTrace;
    }

    @Override
    public String toString() {
        return "Result{" + "hasCrashed=" + hasCrashed + ", didTimeout=" + didTimeout + ", startTime=" + startTime
                + ", stopTime=" + stopTime + ", edges=" + branchTrace.toString() + '}';
    }

    public TestVector getVector() {
        return vector;
    }

    private static final Logger LOG = Logger.getLogger(Result.class.getName());
}
