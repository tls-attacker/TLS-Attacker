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
    private EvolutionaryFuzzerConfig evoConfig;
    private int found = 0;

    public IsCrashRules(EvolutionaryFuzzerConfig evoConfig) {
	this.evoConfig = evoConfig;
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
	File f = new File(evoConfig.getOutputFolder() + "crash/" + result.getId());
	try {
	    result.getExecutedTrace().setDescription("WorkflowTrace crashed!");
	    f.createNewFile();
	    WorkflowTraceSerializer.write(f, result.getExecutedTrace());
	} catch (JAXBException | IOException E) {
	    LOG.log(Level.SEVERE, "Could not write Results to Disk! Does the Fuzzer have the rights to write to {0}",
		    f.getAbsolutePath());
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
