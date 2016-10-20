/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer;

import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.result.Result;

/**
 * An analyzer implementation which uses a set of Rules to find interesting
 * TestVectors.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class RuleAnalyzer extends Analyzer {

    /**
     *
     */
    public static final String optionName = "rule";

    /**
     *
     */
    private final List<Rule> ruleList;

    /**
     *
     */
    private final EvolutionaryFuzzerConfig config;

    /**
     * 
     * @param config
     */
    public RuleAnalyzer(EvolutionaryFuzzerConfig config) {
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
	ruleList.add(new AnalyzeGoodModificationRule(config));
	ruleList.add(new ProtocolVersionRule(config));
	ruleList.add(new EarlyHeartbeatRule(config));
    }

    /**
     * 
     * @param tempClass
     * @return
     */
    public Rule getRule(Class tempClass) {
	for (Rule r : ruleList) {
	    if (r.getClass().equals(tempClass)) {
		return r;
	    }
	}
	return null;
    }

    /**
     * 
     * @param result
     */
    public void analyze(Result result) {
	for (Rule r : ruleList) {
	    if (r.applies(result)) {
		r.onApply(result);
	    } else {
		r.onDecline(result);
	    }
	}
    }

    /**
     * 
     * @return
     */
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

    private static final Logger LOG = Logger.getLogger(RuleAnalyzer.class.getName());

}
