/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer;

import tlsattacker.fuzzer.config.analyzer.FindAlertsRuleConfig;
import tlsattacker.fuzzer.config.analyzer.IsGoodRuleConfig;
import tlsattacker.fuzzer.config.analyzer.IsTimeoutRuleConfig;
import tlsattacker.fuzzer.config.analyzer.UniqueFlowsRuleConfig;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.result.Result;
import tlsattacker.fuzzer.testvector.TestVectorSerializer;
import de.rub.nds.tlsattacker.tls.config.WorkflowTraceSerializer;
import java.io.File;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBException;

/**
 * A rule which records TestVectors that caused a timeout.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class IsTimeoutRule extends Rule {
    private static final Logger LOG = Logger.getLogger(IsTimeoutRule.class.getName());
    private int found = 0;
    private IsTimeoutRuleConfig config;

    public IsTimeoutRule(EvolutionaryFuzzerConfig evoConfig) {
	super(evoConfig, "is_timeout.rule");
	File f = new File(evoConfig.getAnalyzerConfigFolder() + configFileName);
	if (f.exists()) {
	    config = JAXB.unmarshal(f, IsTimeoutRuleConfig.class);
	}
	if (config == null) {
	    config = new IsTimeoutRuleConfig();
	    writeConfig(config);
	}
	prepareConfigOutputFolder();
    }

    @Override
    public boolean applies(Result result) {
	if (result.didTimeout()) {
	    return true;
	} else {
	    return false;
	}
    }

    @Override
    public void onApply(Result result) {
	found++;
	File f = new File(evoConfig.getOutputFolder() + config.getOutputFolder() + result.getId());
	try {
	    result.getVector().getTrace().setDescription("WorkflowTrace did Timeout!");
	    f.createNewFile();
	    TestVectorSerializer.write(f, result.getVector());
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
	if (found > 0) {
	    return "Found " + found + " Traces which caused the Server to Timeout\n";
	} else {
	    return null;
	}
    }

    @Override
    public IsTimeoutRuleConfig getConfig() {
	return config;
    }


}
