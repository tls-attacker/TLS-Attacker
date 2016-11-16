/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer.rules;

import tlsattacker.fuzzer.config.analyzer.RuleConfig;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.result.AgentResult;
import java.io.File;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXB;

/**
 * A is a class that can be used to analyze TestVectors. It seperates the
 * different things an operator might want to look for in a TestVector into
 * different Classes.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class Rule {

    /**
     * The Folder in which the rule should store its results
     */
    protected File ruleFolder;

    /**
     * The name of the configuration file
     */
    protected final String configFileName;

    /**
     * The EvolutionaryFuzzerConfig object for this rule
     */
    protected EvolutionaryFuzzerConfig evoConfig;

    /**
     * If the rule should be used at all
     */
    private final boolean isActive = true;

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

    /**
     * A method that checks if the Rule should be applied to to a AgentResult
     * 
     * @param result
     *            AgentResult to analyze
     * @return True if the Rule should apply
     */
    public abstract boolean applies(AgentResult result);

    /**
     * This method is called when the applies method returned true
     * 
     * @param result
     *            AgentResult to analyze
     */
    public abstract void onApply(AgentResult result);

    /**
     * This method is called when the applies method returned false
     * 
     * @param result
     */
    public abstract void onDecline(AgentResult result);

    /**
     * Generates a status report
     * 
     * @return
     */
    public abstract String report();

    /**
     * Serializes a Configuration file to its configuration file
     * 
     * @param c
     */
    protected void writeConfig(RuleConfig c) {
        File f = new File(evoConfig.getAnalyzerConfigFolder() + configFileName);
        if (f.exists()) {
            LOG.log(Level.SEVERE, "Config File already exists, not writing new Config:{0}", configFileName);
        } else {
            JAXB.marshal(c, f);
        }
    }

    /**
     * Creates the folders for the rule folder and if clean start is selected,
     * deltes all previously collected data
     */
    protected void prepareConfigOutputFolder() {
        ruleFolder = new File(evoConfig.getOutputFolder() + this.getConfig().getOutputFolder());
        if (evoConfig.isCleanStart()) {
            if (ruleFolder.exists()) {
                for (File tempFile : ruleFolder.listFiles()) {
                    tempFile.delete();
                }
            }
        }
        ruleFolder.mkdirs();
    }

    private static final Logger LOG = Logger.getLogger(Rule.class.getName());
}
