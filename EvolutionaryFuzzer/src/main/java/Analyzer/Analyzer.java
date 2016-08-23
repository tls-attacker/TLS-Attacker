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
import java.util.LinkedList;
import java.util.List;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class Analyzer {
    private List<Rule> ruleList;
    private EvolutionaryFuzzerConfig config;

    public Analyzer(EvolutionaryFuzzerConfig config) {
	this.config = config;
	ruleList = new LinkedList<Rule>();
	// THE IS GOOD RULE SHOULD ALWAYS BE EXECUTED ON THE START
	ruleList.add(new IsGoodRule(config));
	ruleList.add(new FindAlertsRule(config));
	ruleList.add(new IsCrashRule(config));
	ruleList.add(new IsTimeoutRule(config));
	ruleList.add(new AnalyzeTimeRule(config));
	ruleList.add(new UniqueFlowsRule(config));
	ruleList.add(new AnalyzeModificationRule(config));
	ruleList.add(new ProtocolVersionRule(config));
	ruleList.add(new EarlyHeartbeatRule(config));

    }

    public void analyze(Result result) {
	for (Rule r : ruleList) {
	    if (r.applys(result)) {
		r.onApply(result);
	    } else {
		r.onDecline(result);
	    }
	}
    }

    public Rule getRule(Class tempClass) {
	for (Rule r : ruleList) {
	    if (r.getClass().equals(tempClass)) {
		return r;
	    }
	}
	return null;
    }

    public String getReport() {
	StringBuilder builder = new StringBuilder();
	for (Rule r : ruleList) {
	    String temp = r.report();
	    if (temp != null) {
		builder.append(r.report());
	    }
	}
	return builder.toString();
    }
}
