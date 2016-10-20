/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.config;

import java.util.logging.Logger;

/**
 * A singleton which allows all classes access to the configuration file.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
@Deprecated
public class ConfigManager {

    /**
     * 
     * @return
     */
    public static ConfigManager getInstance() {
	return ConfigManagerHolder.INSTANCE;
    }

    /**
     *
     */
    private EvolutionaryFuzzerConfig config;

    /**
     *
     */
    private ConfigManager() {
	config = new EvolutionaryFuzzerConfig();
    }

    /**
     * 
     * @return
     */
    public EvolutionaryFuzzerConfig getConfig() {
	return config;
    }

    /**
     * 
     * @param config
     */
    public void setConfig(EvolutionaryFuzzerConfig config) {
	this.config = config;
    }

    /**
     *
     */
    private static class ConfigManagerHolder {

	/**
         *
         */
	private static final ConfigManager INSTANCE = new ConfigManager();

	/**
         *
         */
	private ConfigManagerHolder() {
	}
    }

    private static final Logger LOG = Logger.getLogger(ConfigManager.class.getName());
}
