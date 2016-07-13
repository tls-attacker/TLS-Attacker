/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Config;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ConfigManager {

    private EvolutionaryFuzzerConfig config;

    public EvolutionaryFuzzerConfig getConfig() {
	return config;
    }

    public void setConfig(EvolutionaryFuzzerConfig config) {
	this.config = config;
    }

    private ConfigManager() {
	config = new EvolutionaryFuzzerConfig();
    }

    public static ConfigManager getInstance() {
	return ConfigManagerHolder.INSTANCE;
    }

    private static class ConfigManagerHolder {

	private static final ConfigManager INSTANCE = new ConfigManager();
    }
}
