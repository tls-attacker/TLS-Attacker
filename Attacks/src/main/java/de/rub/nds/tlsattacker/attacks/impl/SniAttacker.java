/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.SniTestCommandConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Sends different server names in the SNI extension in the ClientHello
 * messages.
 */
public class SniAttacker extends Attacker<SniTestCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(SniAttacker.class);

    public SniAttacker(SniTestCommandConfig config) {
        super(config, false);
    }

    @Override
    public void executeAttack() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Boolean isVulnerable() {
        throw new UnsupportedOperationException("Work in progress");
    }

}
