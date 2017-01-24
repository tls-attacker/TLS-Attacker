/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer.rule;

import tlsattacker.fuzzer.config.analyzer.IsGoodRuleConfig;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.result.MergeResult;
import tlsattacker.fuzzer.result.AgentResult;
import tlsattacker.fuzzer.testvector.TestVectorSerializer;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBException;
import tlsattacker.fuzzer.instrumentation.EmptyInstrumentationMap;
import tlsattacker.fuzzer.instrumentation.InstrumentationMap;

/**
 * A rule which analyzes if the TestVector reached new codepaths and set a flag
 * in the AgentResult object accordingly.
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class IsGoodRule extends Rule {

    /**
     * A Writer object which is used to store timing statistics
     */
    private PrintWriter outWriter;

    /**
     * InstrumentationMap with which other Workflows are merged
     */
    private InstrumentationMap instrumentationMap;

    /**
     * The number of TestVectors that this rule applied to
     */
    private int found = 0;

    /**
     * The configuration object for this rule
     */
    private IsGoodRuleConfig config;

    /**
     * A timestamp of the last seen goodTestVector
     */
    private long lastGoodTimestamp = System.currentTimeMillis();

    public IsGoodRule(EvolutionaryFuzzerConfig evoConfig) {
        super(evoConfig, "is_good.rule");
        File f = new File(evoConfig.getAnalyzerConfigFolder() + configFileName);
        if (f.exists()) {
            config = JAXB.unmarshal(f, IsGoodRuleConfig.class);
        }
        if (config == null) {
            config = new IsGoodRuleConfig();
            writeConfig(config);
        }
        this.instrumentationMap = null;
        prepareConfigOutputFolder();
        try {
            f = new File(evoConfig.getOutputFolder() + config.getOutputFileGraph());
            if (evoConfig.isCleanStart()) {
                f.delete();
                f.createNewFile();
            }
            outWriter = new PrintWriter(new BufferedWriter(new FileWriter(f, true)));
        } catch (IOException ex) {
            LOGGER.error(
                    "IsGoodRule could not initialize the output File! Does the fuzzer have the rights to write to ", ex);
        }
    }

    /**
     * The rule applies if the trace in the AgentResult contains Edges or
     * Codeblocks the rule has not seen before
     *
     * @param result
     *            AgentResult to analyze
     * @return True if the Rule contains new Codeblocks or Branches
     */
    @Override
    public synchronized boolean applies(AgentResult result) {
        if(result.getInstrumentationMap() instanceof EmptyInstrumentationMap)
        {
            return false;
        }
        if (instrumentationMap == null && result.getInstrumentationMap() != null) {
            instrumentationMap = result.getInstrumentationMap();
            return true;
        }

        if (instrumentationMap.didHitNew(result.getInstrumentationMap())) {
            MergeResult r = instrumentationMap.merge(result.getInstrumentationMap());
            LOGGER.debug("Found a GoodTrace:" + r.toString());
            return true;
        } else {
            return false;
        }

    }

    /**
     * Updates statistics and stores the TestVector. Also sets a flag in the
     * TestVector such that other rules know that this TestVector is considered
     * as good.
     *
     * @param result
     *            AgentResult to analyze
     */
    @Override
    public synchronized void onApply(AgentResult result) {
        // Write statistics
        outWriter.println(System.currentTimeMillis() - lastGoodTimestamp);
        outWriter.flush();
        lastGoodTimestamp = System.currentTimeMillis();
        found++;
        result.setGoodTrace(true);
        // It may be that we dont want to safe good Traces, for example if
        // we execute already saved Traces
        if (evoConfig.isSerialize()) {
            File f = new File(evoConfig.getOutputFolder() + config.getOutputFolder() + result.getId());
            try {
                f.createNewFile();
                TestVectorSerializer.write(f, result.getVector());
            } catch (JAXBException | IOException E) {
                LOGGER.error(
                        "Could not write Results to Disk! Does the Fuzzer have the rights to write to "
                                + f.getAbsolutePath(), E);
            }
        }
        result.getVector().getTrace().makeGeneric();
    }

    public synchronized InstrumentationMap getInstrumentationMap() {
        if (instrumentationMap == null) {
            return new EmptyInstrumentationMap();
        }
        return instrumentationMap;
    }

    /**
     * Do nothing
     *
     * @param result
     *            AgentResult to analyze
     */
    @Override
    public void onDecline(AgentResult result) {
        result.setGoodTrace(Boolean.FALSE);
    }

    /**
     * Generates a status report
     *
     * @return
     */
    @Override
    public synchronized String report() {
        return "Good:" + found + " Last Good " + (System.currentTimeMillis() - lastGoodTimestamp) / 1000.0
                + " seconds ago\n";
    }

    @Override
    public IsGoodRuleConfig getConfig() {
        return config;
    }

}
