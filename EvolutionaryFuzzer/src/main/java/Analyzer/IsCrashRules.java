/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Analyzer;

import Config.Analyzer.FindAlertsRuleConfig;
import Config.Analyzer.IsCrashRuleConfig;
import Config.EvolutionaryFuzzerConfig;
import Result.Result;
import TestVector.TestVectorSerializer;
import de.rub.nds.tlsattacker.tls.config.WorkflowTraceSerializer;
import java.io.File;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBException;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class IsCrashRules extends Rule {

    private int found = 0;

    public IsCrashRules(EvolutionaryFuzzerConfig evoConfig) {
	super(evoConfig, "is_crash.rule");
	if (config == null) {
	    config = new IsCrashRuleConfig();
	    writeConfig(config);
	}
	File f = new File(evoConfig.getOutputFolder() + ((IsCrashRuleConfig) config).getOutputFolder());
	f.mkdirs();
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
	File f = new File(evoConfig.getOutputFolder() + ((IsCrashRuleConfig) config).getOutputFolder() + result.getId());
	try {
	    result.getExecutedVector().getTrace().setDescription("WorkflowTrace crashed!");
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
	if (found > 0) {
	    return "Found " + found + " Traces which crashed the Server\n";
	} else {
	    return null;
	}
    }

    private static final Logger LOG = Logger.getLogger(IsCrashRules.class.getName());

}
