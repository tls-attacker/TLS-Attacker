/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls;

import de.rub.nds.tlsattacker.tls.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @param <Config>
 */
public abstract class Attacker<Config extends TLSDelegateConfig> {

    protected Config config;

    protected final boolean saveToScan;

    public Attacker(Config config, boolean saveToScan) {
        this.config = config;
        this.saveToScan = saveToScan;
    }

    /**
     * Executes a given attack.
     * 
     * @param configHandler
     */
    public abstract void executeAttack();

    public abstract Boolean isVulnerable();

    public Config getConfig() {
        return config;
    }
}
