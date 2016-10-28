/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer;

import tlsattacker.fuzzer.config.analyzer.AnalyzeModificationRuleConfig;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.modification.Modification;
import tlsattacker.fuzzer.result.Result;
import java.io.File;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;
import javax.xml.bind.JAXB;

/**
 * A Rule which counts the applied modifications
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AnalyzeModificationRule extends Rule {

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
    public AnalyzeModificationRule(EvolutionaryFuzzerConfig evoConfig) {
	super(evoConfig, "analyze_modification.rule");
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
     * This rule applies to all TestVectors
     * @param result Result to analyze
     * @return True
     */
    @Override
    public boolean applies(Result result) {
	return true;
    }

    /**
     * Counts the modifications on the Result
     * @param result
     */
    @Override
    public void onApply(Result result) {
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
     * Tries to find a ModificationCounter in the counterList, if non is found null is returned
     * @param type Type of counter to search for
     * @return Found counter or null
     */
    public ModificationCounter getCounter(Modification type)
    {
        for(ModificationCounter counter : counterList)
        {
            if(type != null && counter.getType().equals(type.getType()))
            {
                return counter;
            }
        }
        return null;
    }

    /**
     * Do nothing
     * @param result Result to analyze
     */
    @Override
    public void onDecline(Result result) {
    }

    /**
     * Generates a status report
     * @return
     */
    @Override
    public String report() {
	if (executedTraces > 0) {
	    StringBuilder b = new StringBuilder("Modifications applied:\n");
	    for (ModificationCounter counter : counterList) {
		b.append(counter.getType().name()).append(" Count:").append(counter.getCounter()).append("\n");
	    }
	    return b.toString();
	} else {
	    return null;
	}
    }

    public long getExecutedTraces() {
	return executedTraces;
    }

    public List<ModificationCounter> getCounterList() {
	return counterList;
    }

    @Override
    public AnalyzeModificationRuleConfig getConfig() {
	return config;
    }
    
    private static final Logger LOG = Logger.getLogger(AnalyzeGoodModificationRule.class.getName());
}
