/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.config.delegate;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A special GeneralDelegate which allows Attacks to add additional Parameters.
 */
public class GeneralAttackDelegate extends GeneralDelegate {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Default Constructor
     */
    public GeneralAttackDelegate() {
    }

    /**
     * Adjusts the Config according to the specified values.
     *
     * @param config
     *               Config to adjust
     */
    @Override
    public void applyDelegate(Config config) {
        super.applyDelegate(config);
    }
}
