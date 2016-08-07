/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Analyzer;

import Config.Analyzer.RuleConfig;
import Config.EvolutionaryFuzzerConfig;
import Config.Mutator.SimpleMutatorConfig;
import Helper.XMLSerializer;
import Mutator.SimpleMutator;
import Result.Result;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class Rule {

    protected File ruleFolder;
    protected RuleConfig config = null;
    protected final String configFileName;
    protected EvolutionaryFuzzerConfig evoConfig;

    protected Rule(EvolutionaryFuzzerConfig evoConfig, String configFileName) {
	this.configFileName = configFileName;
	this.evoConfig = evoConfig;
	config = TryLoadConfig();
    }

    public File getRuleFolder() {
	return ruleFolder;
    }

    public boolean isActive() {
	return config.isActive();
    }

    public abstract boolean applys(Result result);

    public abstract void onApply(Result result);

    public abstract void onDecline(Result result);

    public abstract String report();

    protected RuleConfig TryLoadConfig() {

	File f = new File(evoConfig.getConfigFolder() + "analyzer/" + configFileName);
	if (f.exists()) {
	    try {
		return (RuleConfig) XMLSerializer.read(f);
	    } catch (FileNotFoundException ex) {
		Logger.getLogger(Rule.class.getName()).log(Level.SEVERE, "Could not read ConfigFile:" + configFileName,
			ex);
	    }
	} else {
	    LOG.log(Level.FINE, "No ConfigFile found:" + configFileName);
	    return null;
	}
	return null;
    }

    protected void writeConfig(RuleConfig c) {
	File f = new File(evoConfig.getConfigFolder() + "analyzer/" + configFileName);
	if (f.exists()) {
	    LOG.log(Level.SEVERE, "Config File already exists, not writing new Config:" + configFileName);
	} else {
	    try {
		XMLSerializer.write(c, f);
	    } catch (FileNotFoundException ex) {
		LOG.log(Level.SEVERE, "Could not write ConfigFile:" + configFileName);
	    }
	}
    }

    private static final Logger LOG = Logger.getLogger(Rule.class.getName());

}
