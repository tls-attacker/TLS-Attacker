package de.rub.nds.tlsattacker.attacks.impl;

/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

import de.rub.nds.tlsattacker.attacks.config.AttackConfig;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @param <Config>
 */
public abstract class Attacker<Config extends AttackConfig> {

    protected Config config;

    protected final boolean saveToScan;

    public Attacker(Config config, boolean saveToScan) {
        this.config = config;
        this.saveToScan = saveToScan;
    }

    /**
     * Executes a given attack.
     */
    public abstract void executeAttack();

    public abstract Boolean isVulnerable();

    public Config getConfig() {
        return config;
    }
}
