/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.config.delegate;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 */
public class GeneralAttackDelegate extends GeneralDelegate {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     *
     */
    public GeneralAttackDelegate() {
    }

    /**
     *
     * @param config
     */
    @Override
    public void applyDelegate(Config config) {
        super.applyDelegate(config);
    }
}
