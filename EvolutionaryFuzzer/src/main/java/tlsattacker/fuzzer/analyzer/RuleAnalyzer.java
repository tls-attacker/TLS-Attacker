/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
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
import tlsattacker.fuzzer.config.FuzzerGeneralConfig;
import tlsattacker.fuzzer.graphs.BranchTrace;
import tlsattacker.fuzzer.result.AgentResult;
import tlsattacker.fuzzer.result.TestVectorResult;

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

    /**
     * The IsGoodRule
     */
    private IsGoodRule goodRule;

    public RuleAnalyzer(EvolutionaryFuzzerConfig config) {
        this.config = config;
        ruleList = new LinkedList<>();
        // THE IS GOOD RULE SHOULD ALWAYS BE EXECUTED ON THE START
        goodRule = new IsGoodRule(config);
        ruleList.add(goodRule);
        ruleList.add(new FindAlertsRule(config));
        ruleList.add(new IsCrashRule(config));
        ruleList.add(new IsTimeoutRule(config));
        ruleList.add(new AnalyzeTimeRule(config));
        ruleList.add(new UniqueFlowsRule(config));
        ruleList.add(new AnalyzeModificationRule(config));
        ruleList.add(new AnalyzeGoodModificationRule(config));
        ruleList.add(new ProtocolVersionRule(config));
        ruleList.add(new EarlyHeartbeatRule(config));
        for (Rule r : ruleList) {
            if (!r.isActive()) {
                ruleList.remove(r);
            }
        }
    }

    /**
     * Returns a rule from the Rule list
     * 
     * @param tempClass
     *            Class of the rule to return
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
     * Analyzes a AgentResult by trying to apply all rules to it
     * 
     * @param result
     */
    @Override
    public void analyze(TestVectorResult result) {
        for (AgentResult agentResult : result.getAgentResults()) {
            for (Rule r : ruleList) {
                if (r.applies(agentResult)) {
                    r.onApply(agentResult);
                } else {
                    r.onDecline(agentResult);
                }
            }
        }
    }

    /**
     * Generates a status report
     * 
     * @return
     */
    @Override
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

    @Override
    public BranchTrace getBranchTrace() {
        if (goodRule.isActive()) {
            return goodRule.getBranchTrace();
        } else {
            return new BranchTrace();
        }
    }

    private static final Logger LOG = Logger.getLogger(RuleAnalyzer.class.getName());
}
