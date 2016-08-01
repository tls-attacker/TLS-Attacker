/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Result;

import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.io.File;
import java.util.logging.Logger;
import Graphs.BranchTrace;
import TestVector.TestVector;

/**
 * This class summarizes a the Results of FuzzingVector. It contains information
 * about a potential timeout, or crash. It containts information about the Time
 * the Vector took to Execute, the Controlflow Branches that were executed by
 * the Vector and the Vector that was executed.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class Result {
    private static final Logger LOG = Logger.getLogger(Result.class.getName());

    // If the Implementation has Crashed

    private final boolean hasCrashed;
    // If the Implementation did Timeout
    private final boolean didTimeout;
    // The Unixtime @ which the Vector started executing
    private final long startTime;
    // The Unixtime @ which the Vector finished executing
    private final long stopTime;
    // File Containing all the ProbeIDs
    private final BranchTrace branchTrace;
    // Workflowtrace that should be Executed
    private final TestVector vector;
    // Workflowtrace that was executed
    private final TestVector executedVector;
    // Each Result get an id for easier referencing, the id is also in
    private final String id;
    private Boolean goodTrace = null;

    public Result(boolean hasCrashed, boolean didTimeout, long startTime, long stopTime, BranchTrace branchTrace,
	    TestVector vector, TestVector executedVector, String id) {
	this.hasCrashed = hasCrashed;
	this.didTimeout = didTimeout;
	this.startTime = startTime;
	this.stopTime = stopTime;
	this.branchTrace = branchTrace;
	this.vector = vector;
	this.executedVector = executedVector;
	this.id = id;
    }

    public Boolean isGoodTrace()
    {
        return goodTrace;
    }

    public void setGoodTrace(Boolean wasGoodTrace)
    {
        this.goodTrace = wasGoodTrace;
    }

    
    /**
     * Returns the ID of the Result
     * 
     * @return ID of the result
     */
    public String getId() {
	return id;
    }

    public TestVector getExecutedVector() {
	return executedVector;
    }

    /**
     * Returns if the Implementation did Crash
     * 
     * @return if the Implementation did Crash
     */
    public boolean hasCrashed() {
	return hasCrashed;
    }

    /**
     * Returns if the Implementation did Timeout
     * 
     * @return if the Implementation did Timeout
     */
    public boolean didTimeout() {
	return didTimeout;
    }

    /**
     * Returns the Unixtime at which the Vector started executing
     * 
     * @return Unixtime at which the Vector started executing
     */
    public long getStartTime() {
	return startTime;
    }

    /**
     * Returns the Unixtime at which the Vector stopped executing
     * 
     * @return Unixtime at which the Vector stopped executing
     */
    public long getStopTime() {
	return stopTime;
    }

    /**
     * Returns a File containing a List of ProbeIDs
     * 
     * @return File containing a List of ProbeIDs
     */
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

}
