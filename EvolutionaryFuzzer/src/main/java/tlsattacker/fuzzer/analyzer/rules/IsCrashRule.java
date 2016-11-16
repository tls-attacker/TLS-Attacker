/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer.rules;

import tlsattacker.fuzzer.config.analyzer.IsCrashRuleConfig;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.result.AgentResult;
import tlsattacker.fuzzer.testvector.TestVectorSerializer;
import java.io.File;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBException;

/**
 * A rule which records TestVectors that crash the server
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class IsCrashRule extends Rule {

    /**
     * The number of TestVectors that this rule applied to
     */
    private int found = 0;

    /**
     * The configuration object for this rule
     */
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

    /**
     * The rule applies if the TestVector caused the Server to crash
     * 
     * @param result
     *            AgentResult to analyze
     * @return
     */
    @Override
    public boolean applies(AgentResult result) {
        return result.hasCrashed();
    }

    /**
     * Stores the TestVector
     * 
     * @param result
     *            AgentResult to analyze
     */
    @Override
    public synchronized void onApply(AgentResult result) {
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

    /**
     * Do nothing
     * 
     * @param result
     *            AgentResult to analyze
     */
    @Override
    public void onDecline(AgentResult result) {
    }

    /**
     * Generates a status report
     * 
     * @return
     */
    @Override
    public synchronized String report() {
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
