/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer;

import tlsattacker.fuzzer.config.analyzer.AnalyzeModificationRuleConfig;
import tlsattacker.fuzzer.config.analyzer.AnalyzeTimeRuleConfig;
import tlsattacker.fuzzer.config.analyzer.UniqueFlowsRuleConfig;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.result.Result;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.DecimalFormat;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXB;

/**
 * A rule which keeps track of different execution time statistics
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AnalyzeTimeRule extends Rule {
    private static DecimalFormat decimalFormat = new DecimalFormat("0.##");
    private static final Logger LOG = Logger.getLogger(AnalyzeTimeRule.class.getName());
    private PrintWriter outWriter;
    private double executedTimeTotal;
    private int numberExecutedTraces = 0;
    private double slowestTime = Double.MIN_VALUE;
    private double fastestTime = Double.MAX_VALUE;
    private AnalyzeTimeRuleConfig config;

    public AnalyzeTimeRule(EvolutionaryFuzzerConfig evoConfig) {
	super(evoConfig, "analyze_time.rule");
	File f = new File(evoConfig.getAnalyzerConfigFolder() + configFileName);
	if (f.exists()) {
	    config = JAXB.unmarshal(f, AnalyzeTimeRuleConfig.class);
	}
	if (config == null) {
	    config = new AnalyzeTimeRuleConfig();
	    writeConfig(config);
	}
	try {
	    f = new File(evoConfig.getOutputFolder() + config.getOutputFile());
	    if (evoConfig.isCleanStart()) {
		f.delete();
		f.createNewFile();
	    }
	    outWriter = new PrintWriter(new BufferedWriter(new FileWriter(f, true)));
	} catch (IOException ex) {
	    Logger.getLogger(AnalyzeTimeRule.class.getName())
		    .log(Level.SEVERE,
			    "AnalyzeTimeRule could not initialize the output File! Does the fuzzer have the rights to write to ",
			    ex);
	}
    }

    @Override
    public boolean applies(Result result) {
	return true;
    }

    @Override
    public void onApply(Result result) {
	numberExecutedTraces++;
	executedTimeTotal += (result.getStopTime() - result.getStartTime());
	if ((result.getStopTime() - result.getStartTime()) > slowestTime) {
	    slowestTime = (result.getStopTime() - result.getStartTime());
	}
	if ((result.getStopTime() - result.getStartTime()) < fastestTime) {
	    fastestTime = (result.getStopTime() - result.getStartTime());
	}
	outWriter.println(result.getId() + "," + (result.getStopTime() - result.getStartTime()));
	outWriter.flush();
    }

    @Override
    public void onDecline(Result result) {
    }

    @Override
    public String report() {
	if (numberExecutedTraces > 0) {
	    return "Executed: " + numberExecutedTraces + " Highest:" + decimalFormat.format(slowestTime / 1000)
		    + "s Lowest:" + decimalFormat.format(fastestTime / 1000) + "s Medium:"
		    + decimalFormat.format((executedTimeTotal / numberExecutedTraces) / 1000) + "s Traces/Second:"
		    + decimalFormat.format(numberExecutedTraces / (executedTimeTotal / 1000)) + "\n";
	} else {
	    return null;
	}
    }

    @Override
    public AnalyzeTimeRuleConfig getConfig() {
	return config;
    }

    public double getExecutedTimeTotal() {
	return executedTimeTotal;
    }

    public int getNumberExecutedTraces() {
	return numberExecutedTraces;
    }

    public double getSlowestTime() {
	return slowestTime;
    }

    public double getFastestTime() {
	return fastestTime;
    }


}
