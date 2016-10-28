/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer.rules;

import tlsattacker.fuzzer.config.analyzer.UniqueFlowsRuleConfig;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.result.Result;
import tlsattacker.fuzzer.testvector.TestVectorSerializer;
import tlsattacker.fuzzer.workflow.WorkflowTraceType;
import tlsattacker.fuzzer.workflow.WorkflowTraceTypeManager;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBException;
import tlsattacker.fuzzer.testvector.TestVector;

/**
 * A rule which finds different executed protocol flows and records them.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class UniqueFlowsRule extends Rule {

    /**
     * The configuration object for this rule
     */
    private UniqueFlowsRuleConfig config;

    /**
     * A set of already discovered unique WorkflowTraceTypes
     */
    private final Set<WorkflowTraceType> typeSet;

    /**
     * The number of TestVectors that this rule applied to
     */
    private int found = 0;

    public UniqueFlowsRule(EvolutionaryFuzzerConfig evoConfig) {
	super(evoConfig, "unique_flows.rule");
	File f = new File(evoConfig.getAnalyzerConfigFolder() + configFileName);
	if (f.exists()) {
	    config = JAXB.unmarshal(f, UniqueFlowsRuleConfig.class);
	}
	if (config == null) {
	    config = new UniqueFlowsRuleConfig();
	    writeConfig(config);
	}
	typeSet = new HashSet<>();
	prepareConfigOutputFolder();
	List<TestVector> oldTestVectors = TestVectorSerializer.readFolder(getRuleFolder());
	for (TestVector vector : oldTestVectors) {
	    typeSet.add(WorkflowTraceTypeManager.generateWorkflowTraceType(vector.getTrace(), ConnectionEnd.CLIENT));
	}

    }

    /**
     * The rule applies if the WorkflowTracetype of the Result has not yet been seen by this rule
     * @param result Result to analyze
     * @return True if the WorkflowTracetype has not yet been seen by this rule
     */
    @Override
    public boolean applies(Result result) {
	WorkflowTraceType type = WorkflowTraceTypeManager.generateWorkflowTraceType(result.getVector().getTrace(),
		ConnectionEnd.CLIENT);
	type.clean();
	return !typeSet.contains(type);

    }

    /**
     * Stores the TestVector and adds the WorkflowTraceType to the set
     * @param result Result to analyze
     */
    @Override
    public void onApply(Result result) {

	WorkflowTraceType type = WorkflowTraceTypeManager.generateWorkflowTraceType(result.getVector().getTrace(),
		ConnectionEnd.CLIENT);
	type.clean();
	if (typeSet.add(type)) {
	    found++;
	    // It may be that we dont want to safe good Traces, for example if
	    // we execute already saved Traces
	    LOG.log(Level.FINE, "Found a new WorkFlowTraceType");
	    LOG.log(Level.FINER, type.toString());
	    File f = new File(evoConfig.getOutputFolder() + config.getOutputFolder() + result.getId());
	    try {
		f.createNewFile();
		TestVectorSerializer.write(f, result.getVector());
	    } catch (JAXBException | IOException E) {
		LOG.log(Level.SEVERE, "Could not write Results to Disk! Does the Fuzzer have the rights to write to "
			+ f.getAbsolutePath(), E);
	    }
	}

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
	return "WorkflowTraceTypes observed:" + typeSet.size() + " WorkFlowTraceTypes found:" + found + "\n";
    }

    @Override
    public UniqueFlowsRuleConfig getConfig() {
	return config;
    }

    private static final Logger LOG = Logger.getLogger(UniqueFlowsRule.class.getName());
}
