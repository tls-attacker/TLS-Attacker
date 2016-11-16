/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls;

import de.rub.nds.tlsattacker.tls.config.CommandConfig;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.util.LinkedList;
import java.util.List;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @param <Config>
 */
public abstract class Attacker<Config extends CommandConfig> {

    protected Config config;

    protected boolean vulnerable;

    /**
     * Tls Contexts stored for logging purposes
     */
    protected List<TlsContext> tlsContexts;

    public Attacker(Config config) {
        this.config = config;
        tlsContexts = new LinkedList<>();
    }

    /**
     * Executes a given attack.
     * 
     * @param configHandler
     */
    public abstract void executeAttack(ConfigHandler configHandler);

    public Config getConfig() {
        return config;
    }

    public void setConfig(Config config) {
        this.config = config;
    }

    public List<TlsContext> getTlsContexts() {
        return tlsContexts;
    }

    public void setTlsContexts(List<TlsContext> tlsContexts) {
        this.tlsContexts = tlsContexts;
    }

    public boolean isVulnerable() {
        return vulnerable;
    }

    public void setVulnerable(boolean vulnerable) {
        this.vulnerable = vulnerable;
    }
}
