/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Analyzer;

import Config.EvolutionaryFuzzerConfig;
import Result.Result;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AnalyzeTimeRule extends Rule {

    private EvolutionaryFuzzerConfig evoConfig;
    private FileWriter fw;
    private BufferedWriter bw;
    private PrintWriter out;
    private long executedTime;
    private long executedTraces = 0;
    private long highest = Long.MIN_VALUE;
    private long lowest = Long.MAX_VALUE;

    public AnalyzeTimeRule(EvolutionaryFuzzerConfig evoConfig) {
	try {
	    this.evoConfig = evoConfig;
	    File f = new File(evoConfig.getOutputFolder() + "/timing.results");
	    fw = new FileWriter(f, true);
	    bw = new BufferedWriter(fw);
	    out = new PrintWriter(bw);
	} catch (IOException ex) {
	    Logger.getLogger(AnalyzeTimeRule.class.getName())
		    .log(Level.SEVERE,
			    "AnalyzeTimeRule could not initialize the output File! Does the fuzzer have the rights to write to ",
			    ex);
	}
    }

    @Override
    public boolean applys(Result result) {
	executedTraces++;
	return true;
    }

    @Override
    public void onApply(Result result) {
	executedTime += (result.getStopTime() - result.getStartTime());
	if ((result.getStopTime() - result.getStartTime()) > highest) {
	    highest = (result.getStopTime() - result.getStartTime());
	}
	if ((result.getStopTime() - result.getStartTime()) < lowest) {
	    lowest = (result.getStopTime() - result.getStartTime());
	}
	out.println(result.getId() + "," + (result.getStopTime() - result.getStartTime()));
	out.flush();
    }

    @Override
    public void onDecline(Result result) {
    }

    @Override
    public String report() {
	if (executedTraces > 0) {
	    return "Executed: " + executedTraces + " Highest:" + highest / 1000 + "s Lowest:" + lowest / 1000
		    + "s Medium:" + (executedTime / executedTraces) / 1000 + "s Traces/Second:"
		    + (double) (executedTraces) / (double) (executedTime / 1000) + "\n";
	} else {
	    return null;
	}
    }

    private static final Logger LOG = Logger.getLogger(AnalyzeTimeRule.class.getName());

}
