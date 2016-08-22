/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Analyzer;

import Config.Analyzer.AnalyzeModificationRuleConfig;
import Config.Analyzer.UniqueFlowsRuleConfig;
import Config.EvolutionaryFuzzerConfig;
import Helper.XMLSerializer;
import Modification.Modification;
import Modification.ModificationType;
import Result.Result;
import de.rub.nds.tlsattacker.wrapper.MutableInt;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AnalyzeModificationRule extends Rule {

    private long executedTraces = 0;
    private HashMap<ModificationType, MutableInt> typeMap;
    private AnalyzeModificationRuleConfig config;

    public AnalyzeModificationRule(EvolutionaryFuzzerConfig evoConfig) {
	super(evoConfig, "analyze_modification.rule");
	config = (AnalyzeModificationRuleConfig) TryLoadConfig();
	if (config == null) {
	    config = new AnalyzeModificationRuleConfig();
	    writeConfig(config);
	}
	typeMap = new HashMap<>();

    }

    @Override
    public boolean applys(Result result) {
	return true;
    }

    @Override
    public void onApply(Result result) {
	executedTraces++;
	for (Modification mod : result.getExecutedVector().getModificationList()) {
	    MutableInt i = typeMap.get(mod.getType());
	    if (i == null) {
		typeMap.put(mod.getType(), new MutableInt(1));
	    } else {
		i.addValue(1);
	    }
	}
    }

    @Override
    public void onDecline(Result result) {
    }

    @Override
    public String report() {
	if (executedTraces > 0) {
	    StringBuilder b = new StringBuilder("Modifications which lead to good Traces:\n");
	    for (Entry<ModificationType, MutableInt> e : typeMap.entrySet()) {
		b.append(e.getKey().name() + " Count:" + e.getValue().getValue() + "\n");
	    }
	    return b.toString();
	} else {
	    return null;
	}
    }

    public long getExecutedTraces() {
	return executedTraces;
    }

    public HashMap<ModificationType, MutableInt> getTypeMap() {
	// TODO can we do sth like unmodifiable map?
	return typeMap;
    }

    @Override
    public AnalyzeModificationRuleConfig getConfig() {
	return config;
    }

    private static final Logger LOG = Logger.getLogger(AnalyzeModificationRule.class.getName());

}
