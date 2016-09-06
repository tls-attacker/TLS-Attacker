/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer;

import tlsattacker.fuzzer.config.analyzer.RuleConfig;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.result.Result;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXB;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class Rule {

    protected File ruleFolder;
    protected final String configFileName;
    protected EvolutionaryFuzzerConfig evoConfig;
    private boolean isActive = true;

    protected Rule(EvolutionaryFuzzerConfig evoConfig, String configFileName) {
	this.configFileName = configFileName;
	this.evoConfig = evoConfig;
    }

    public File getRuleFolder() {
	return ruleFolder;
    }

    public boolean isActive() {
	return isActive;
    }

    public abstract RuleConfig getConfig();

    public abstract boolean applys(Result result);

    public abstract void onApply(Result result);

    public abstract void onDecline(Result result);

    public abstract String report();

    protected void writeConfig(RuleConfig c) {
	File f = new File(evoConfig.getAnalyzerConfigFolder() + configFileName);
	if (f.exists()) {
	    LOG.log(Level.SEVERE, "Config File already exists, not writing new Config:" + configFileName);
	} else {
	    JAXB.marshal(c, f);
	}
    }

    protected void prepareConfigOutputFolder() {
	File f = new File(evoConfig.getOutputFolder() + this.getConfig().getOutputFolder());
	if (evoConfig.isCleanStart()) {
	    if (f.exists()) {
		for (File tempFile : f.listFiles()) {
		    tempFile.delete();
		}
	    }
	}
	f.mkdirs();
    }

    private static final Logger LOG = Logger.getLogger(Rule.class.getName());

}
