/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Analyzer;

import Config.Analyzer.FindAlertsRuleConfig;
import Config.Analyzer.IsTimeoutRuleConfig;
import Config.Analyzer.RuleConfig;
import Config.Analyzer.UniqueFlowsRuleConfig;
import Config.EvolutionaryFuzzerConfig;
import Graphs.BranchTrace;
import Result.Result;
import TestVector.TestVectorSerializer;
import WorkFlowType.WorkflowTraceType;
import WorkFlowType.WorkflowTraceTypeManager;
import de.rub.nds.tlsattacker.tls.config.WorkflowTraceSerializer;
import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBException;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class UniqueFlowsRule extends Rule {

    private static final Logger LOG = Logger.getLogger(UniqueFlowsRule.class.getName());
    private UniqueFlowsRuleConfig config;
    private final Set<WorkflowTraceType> typeSet;
    private int found = 0;

    public UniqueFlowsRule(EvolutionaryFuzzerConfig evoConfig) {
	super(evoConfig, "unique_flows.rule");
	config = (UniqueFlowsRuleConfig) TryLoadConfig();
	if (config == null) {
	    config = new UniqueFlowsRuleConfig();
	    writeConfig(config);
	}
	typeSet = new HashSet<>();
	prepareConfigFolder();
    }

    @Override
    public boolean applys(Result result) {
	WorkflowTraceType type = WorkflowTraceTypeManager.generateWorkflowTraceType(result.getExecutedVector()
		.getTrace());
	type.clean();
	return !typeSet.contains(type);

    }

    @Override
    public void onApply(Result result) {
	found++;
	WorkflowTraceType type = WorkflowTraceTypeManager.generateWorkflowTraceType(result.getExecutedVector()
		.getTrace());
	type.clean();
	typeSet.add(type);// TODO Can this be a race?
	// It may be that we dont want to safe good Traces, for example if
	// we execute already saved Traces
	LOG.log(Level.FINE, "Found a new WorkFlowTraceType");
	LOG.log(Level.FINER, type.toString());
	File f = new File(evoConfig.getOutputFolder() + config.getOutputFolder() + result.getId());
	try {
	    f.createNewFile();
	    TestVectorSerializer.write(f, result.getExecutedVector());
	} catch (JAXBException | IOException E) {
	    LOG.log(Level.SEVERE,
		    "Could not write Results to Disk! Does the Fuzzer have the rights to write to "
			    + f.getAbsolutePath(), E);
	}
    }

    @Override
    public void onDecline(Result result) {
    }

    @Override
    public String report() {
	return "WorkflowTraceTypes observed:" + typeSet.size() + " WorkFlowTraceTypes found:" + found + "\n";
    }

    @Override
    public UniqueFlowsRuleConfig getConfig() {
	return config;
    }

}
