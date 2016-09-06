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
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class IsCrashRule extends Rule {

    private int found = 0;
    private IsCrashRuleConfig config;

    public IsCrashRule(EvolutionaryFuzzerConfig evoConfig) {
	super(evoConfig, "is_crash.rule");
	File f = new File(evoConfig.getAnalyzerConfigFolder() + configFileName);
	if (f.exists()) {
	    config = JAXB.unmarshal(f, IsCrashRuleConfig.class);
	}
	if (config == null) {
	    config = new IsCrashRuleConfig();
	    writeConfig(config);
	}
	prepareConfigOutputFolder();
    }

    @Override
    public boolean applys(Result result) {
	if (result.hasCrashed()) {
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
	    result.getVector().getTrace().setDescription("WorkflowTrace crashed!");
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
	    return "Found " + found + " Traces which crashed the Server\n";
	} else {
	    return null;
	}
    }

    @Override
    public IsCrashRuleConfig getConfig() {
	return config;
    }

    private static final Logger LOG = Logger.getLogger(IsCrashRule.class.getName());

}
