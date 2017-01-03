/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer.rules;

import tlsattacker.fuzzer.analyzer.helpers.ModificationCounter;
import tlsattacker.fuzzer.config.analyzer.AnalyzeModificationRuleConfig;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.modification.Modification;
import tlsattacker.fuzzer.result.AgentResult;
import java.io.File;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.JAXB;

/**
 * A Rule which counts the applied modifications which resulted in good
 * TestVectors
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AnalyzeGoodModificationRule extends Rule {

    /**
     * The number of TestVectors this rule saw
     */
    private long executedTraces = 0;

    /**
     * A list which stores counters how often it saw each modification type
     */
    private final List<ModificationCounter> counterList;

    /**
     * The configuration object for this rule
     */
    private AnalyzeModificationRuleConfig config;

    /**
     * 
     * @param evoConfig
     */
    public AnalyzeGoodModificationRule(EvolutionaryFuzzerConfig evoConfig) {
        super(evoConfig, "analyze_good_modification.rule");
        File f = new File(evoConfig.getAnalyzerConfigFolder() + configFileName);
        if (f.exists()) {
            config = JAXB.unmarshal(f, AnalyzeModificationRuleConfig.class);
        }
        if (config == null) {
            config = new AnalyzeModificationRuleConfig();
            writeConfig(config);
        }
        counterList = new LinkedList<>();

    }

    /**
     * This method returns true if the TestVector in the AgentResult is
     * conisdered as a good TestVector
     * 
     * @param result
     *            AgentResult to analyze
     * @return True if TestVector is good
     */
    @Override
    public boolean applies(AgentResult result) {
        return result.isGoodTrace() == Boolean.TRUE;
    }

    /**
     * Counts the modifications on the AgentResult
     * 
     * @param result
     */
    @Override
    public synchronized void onApply(AgentResult result) {
        executedTraces++;
        for (Modification mod : result.getVector().getModificationList()) {
            ModificationCounter counter = getCounter(mod);
            if (counter == null) {
                counter = new ModificationCounter(mod.getType());
                counter.incrementCounter();
                counterList.add(counter);
            } else {
                counter.incrementCounter();
            }
        }
    }

    /**
     * Tries to find a ModificationCounter in the counterList, if non is found
     * null is returned
     * 
     * @param type
     *            Type of counter to search for
     * @return Found counter or null
     */
    public synchronized ModificationCounter getCounter(Modification type) {
        for (ModificationCounter counter : counterList) {
            if (type != null && counter.getType().equals(type.getType())) {
                return counter;
            }
        }
        return null;
    }

    /**
     * Do nothing
     * 
     * @param result
     *            AgentResult to analyze
     */
    @Override
    public void onDecline(AgentResult result) {
    }

    /**
     * Generates a status report
     * 
     * @return
     */
    @Override
    public synchronized String report() {
        if (executedTraces > 0) {
            StringBuilder b = new StringBuilder("Modifications which lead to good Traces:\n");
            for (ModificationCounter counter : counterList) {
                b.append(counter.getType().name()).append(" Count:").append(counter.getCounter()).append("\n");
            }
            return b.toString();
        } else {
            return null;
        }
    }

    public synchronized long getExecutedTraces() {
        return executedTraces;
    }

    public synchronized List<ModificationCounter> getCounterList() {
        return counterList;
    }

    @Override
    public AnalyzeModificationRuleConfig getConfig() {
        return config;
    }

}
