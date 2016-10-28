/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer;

import tlsattacker.fuzzer.analyzer.rules.ProtocolVersionRule;
import tlsattacker.fuzzer.analyzer.rules.AnalyzeGoodModificationRule;
import tlsattacker.fuzzer.analyzer.rules.Rule;
import tlsattacker.fuzzer.analyzer.rules.FindAlertsRule;
import tlsattacker.fuzzer.analyzer.rules.UniqueFlowsRule;
import tlsattacker.fuzzer.analyzer.rules.IsGoodRule;
import tlsattacker.fuzzer.analyzer.rules.IsTimeoutRule;
import tlsattacker.fuzzer.analyzer.rules.AnalyzeModificationRule;
import tlsattacker.fuzzer.analyzer.rules.EarlyHeartbeatRule;
import tlsattacker.fuzzer.analyzer.rules.AnalyzeTimeRule;
import tlsattacker.fuzzer.analyzer.rules.IsCrashRule;
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
     * The name of the Analayzer when referred by command line
     */
    public static final String optionName = "rule";

    /**
     * The list of Rules the analyzer uses
     */
    private final List<Rule> ruleList;

    /**
     * The EvolutionaryFuzzerConfig object for this the Analyzer uses
     */
    private final EvolutionaryFuzzerConfig config;

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
     * Returns a rule from the Rule list
     * @param tempClass Class of the rule to return
     * @return First Rule from the rule list of matching class
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
     * Analyzes a Result by trying to apply all rules to it
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
     * Generates a status report
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
