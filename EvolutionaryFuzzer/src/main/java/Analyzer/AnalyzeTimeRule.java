/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Analyzer;

import Config.Analyzer.AnalyzeModificationRuleConfig;
import Config.Analyzer.AnalyzeTimeRuleConfig;
import Config.EvolutionaryFuzzerConfig;
import Result.Result;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.DecimalFormat;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AnalyzeTimeRule extends Rule {
    private FileWriter fw;
    private BufferedWriter bw;
    private PrintWriter out;
    private double executedTime;
    private double executedTraces = 0;
    private double highest = Double.MIN_VALUE;
    private double lowest = Double.MAX_VALUE;
    private static DecimalFormat df2 = new DecimalFormat("0.##");

    public AnalyzeTimeRule(EvolutionaryFuzzerConfig evoConfig) {
	super(evoConfig, "analyze_time.rule");
	if (config == null) {
	    config = new AnalyzeTimeRuleConfig();
	    writeConfig(config);
	}
	try {
	    File f = new File(evoConfig.getOutputFolder() + ((AnalyzeTimeRuleConfig) config).getOutputFile());

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
	    return "Executed: " + executedTraces + " Highest:" + df2.format(highest / 1000) + "s Lowest:"
		    + df2.format(lowest / 1000) + "s Medium:" + df2.format((executedTime / executedTraces) / 1000)
		    + "s Traces/Second:" + df2.format(executedTraces / (executedTime / 1000)) + "\n";
	} else {
	    return null;
	}
    }

    private static final Logger LOG = Logger.getLogger(AnalyzeTimeRule.class.getName());

}
