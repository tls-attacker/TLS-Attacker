/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
import de.rub.nds.tlsattacker.attacks.config.AttackConfig;
import de.rub.nds.tlsattacker.attacks.connectivity.ConnectivityChecker;
import de.rub.nds.tlsattacker.core.config.Config;
import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @param <AttConfig>
 */
public abstract class Attacker<AttConfig extends AttackConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     *
     */
    protected AttConfig config;

    private final Config baseConfig;

    /**
     *
     * @param config
     * @param baseConfig
     */
    public Attacker(AttConfig config, Config baseConfig) {
        this.config = config;
        this.baseConfig = baseConfig;
    }

    /**
     *
     */
    public void attack() {
        LOGGER.debug("Attacking with: " + this.getClass().getSimpleName());
        if (!config.isSkipConnectionCheck()) {
            if (!canConnect()) {
                CONSOLE.warn("Cannot reach Server. Is the server online?");
                return;
            }
        }
        executeAttack();
    }

    /**
     *
     * @return
     */
    public Boolean checkVulnerability() {
        LOGGER.debug("Checking: " + this.getClass().getSimpleName());
        if (!config.isSkipConnectionCheck()) {
            if (!canConnect()) {
                CONSOLE.warn("Cannot reach Server. Is the server online?");
                return null;
            } else {
                LOGGER.debug("Can connect to server. Running vulnerability scan");
            }
        }
        return isVulnerable();
    }

    /**
     * Executes a given attack.
     */
    protected abstract void executeAttack();

    /**
     *
     * @return
     */
    protected abstract Boolean isVulnerable();

    /**
     *
     * @return
     */
    public AttConfig getConfig() {
        return config;
    }

    /**
     *
     * @return
     */
    public Config getTlsConfig() {
        if (!config.hasDifferentConfig() && baseConfig == null) {
            return config.createConfig();
        } else {
            return config.createConfig(baseConfig);
        }
    }

    /**
     *
     * @return
     */
    public Config getBaseConfig() {
        return baseConfig.createCopy();
    }

    /**
     *
     * @return
     */
    protected Boolean canConnect() {
        Config tlsConfig = config.createConfig();
        ConnectivityChecker checker = new ConnectivityChecker(tlsConfig.getDefaultClientConnection());
        return checker.isConnectable();
    }
}
