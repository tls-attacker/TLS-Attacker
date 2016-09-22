/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer;

import tlsattacker.fuzzer.config.analyzer.FindAlertsRuleConfig;
import tlsattacker.fuzzer.config.analyzer.IsCrashRuleConfig;
import tlsattacker.fuzzer.config.analyzer.IsGoodRuleConfig;
import tlsattacker.fuzzer.config.analyzer.UniqueFlowsRuleConfig;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.graphs.BranchTrace;
import tlsattacker.fuzzer.graphs.CountEdge;
import tlsattacker.fuzzer.graphs.ProbeVertex;
import tlsattacker.fuzzer.result.MergeResult;
import tlsattacker.fuzzer.result.Result;
import tlsattacker.fuzzer.result.ResultContainer;
import tlsattacker.fuzzer.testvector.TestVectorSerializer;
import de.rub.nds.tlsattacker.tls.config.WorkflowTraceSerializer;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBException;
import org.jgrapht.DirectedGraph;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class IsGoodRule extends Rule {

    private PrintWriter outWriter;
    private static final Logger LOG = Logger.getLogger(IsGoodRule.class.getName());
    // BranchTrace with which other Workflows are merged
    private final BranchTrace branch;
    private int found = 0;
    private IsGoodRuleConfig config;
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
	this.branch = new BranchTrace();
	prepareConfigOutputFolder();
	try {
	    f = new File(evoConfig.getOutputFolder() + config.getOutputFileGraph());
	    if (evoConfig.isCleanStart()) {
		f.delete();
		f.createNewFile();
	    }
	    outWriter = new PrintWriter(new BufferedWriter(new FileWriter(f, true)));
	} catch (IOException ex) {
	    Logger.getLogger(AnalyzeTimeRule.class.getName())
		    .log(Level.SEVERE,
			    "AnalyzeTimeRule could not initialize the output File! Does the fuzzer have the rights to write to ",
			    ex);
	}
    }

    @Override
    public boolean applys(Result result) {
	MergeResult r = null;
	r = branch.merge(result.getBranchTrace());

	if (r != null && (r.getNewBranches() > 0 || r.getNewVertices() > 0)) {
	    LOG.log(Level.FINE, "Found a GoodTrace:{0}", r.toString());
	    return true;
	} else {
	    return false;
	}

    }

    @Override
    public void onApply(Result result) {
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
		LOG.log(Level.SEVERE, "Could not write Results to Disk! Does the Fuzzer have the rights to write to "
			+ f.getAbsolutePath(), E);
	    }
	}
	result.getVector().getTrace().makeGeneric();
    }

    public BranchTrace getBranchTrace() {
	return branch;
    }

    @Override
    public void onDecline(Result result) {
	result.setGoodTrace(Boolean.FALSE);
    }

    @Override
    public String report() {
	return "Vertices:" + branch.getVerticesCount() + " Edges:" + branch.getBranchCount() + " Good:" + found
		+ " Last Good " + (double) (System.currentTimeMillis() - lastGoodTimestamp) / 1000.0 + " seconds ago\n";
    }

    @Override
    public IsGoodRuleConfig getConfig() {
	return config;
    }
}
