/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer;

import java.util.logging.Logger;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.exceptions.IllegalAnalyzerException;

/**
 * A factory class which generates the correct Analyzer depending on the
 * Analyzer specified in the configuration object
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AnalyzerFactory {

    /**
     * Chooses the correct Analyzer depending on the Analyzer specified in
     * the config
     * 
     * @param config
     *            Config object to use
     * @return Correct Analyzer instance
     */
    public static Analyzer getAnalyzer(EvolutionaryFuzzerConfig config) throws IllegalAnalyzerException  {
        switch (config.getAnalyzer()) {
            case RuleAnalyzer.optionName:
                return new RuleAnalyzer(config);
            case FingerprintAnalyzer.optionName:
                return new FingerprintAnalyzer(config);
            default:
                throw new IllegalAnalyzerException("Illegal Value for Analyzer:" + config.getAnalyzer());
        }
    }

    /**
     *
     */
    private AnalyzerFactory() {
    }

    private static final Logger LOG = Logger.getLogger(AnalyzerFactory.class.getName());
}
