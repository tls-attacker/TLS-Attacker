/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer.rules;

import tlsattacker.fuzzer.config.analyzer.AnalyzeTimeRuleConfig;
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

    /**
     * The Decimal format in the reports()
     */
    private static final DecimalFormat decimalFormat = new DecimalFormat("0.##");

    /**
     * A writer to which statistics are written too
     */
    private PrintWriter outWriter;

    /**
     * Time for which the fuzzer is already running totally (all Threads
     * combined)
     */
    private double executedTimeTotal;

    /**
     * The number of TestVectors this rule saw
     */
    private int numberExecutedTraces = 0;

    /**
     * Slowest execution time in ms
     */
    private double slowestTime = Double.MIN_VALUE;

    /**
     * Fastest execution time in ms
     */
    private double fastestTime = Double.MAX_VALUE;

    /**
     * Configuration for this ruĺe
     */
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

    /**
     * The rule always applies
     * 
     * @param result
     *            Result to analyze
     * @return True
     */
    @Override
    public boolean applies(Result result) {
        return true;
    }

    /**
     * Updates timing statistics
     * 
     * @param result
     *            Result to analyze
     */
    @Override
    public synchronized void onApply(Result result) {
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

    /**
     * Do nothing
     * 
     * @param result
     *            Result to analyze
     */
    @Override
    public void onDecline(Result result) {
    }

    /**
     * Generates a status report
     * 
     * @return
     */
    @Override
    public synchronized String report() {
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

    public synchronized double getExecutedTimeTotal() {
        return executedTimeTotal;
    }

    public synchronized int getNumberExecutedTraces() {
        return numberExecutedTraces;
    }

    public synchronized double getSlowestTime() {
        return slowestTime;
    }

    public synchronized double getFastestTime() {
        return fastestTime;
    }

    private static final Logger LOG = Logger.getLogger(AnalyzeTimeRule.class.getName());
}
