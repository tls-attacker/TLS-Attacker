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
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import java.security.Provider;
import java.security.Security;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GeneralAttackDelegate extends GeneralDelegate {

    private static final Logger LOGGER = LogManager.getLogger();

    public GeneralAttackDelegate() {
    }

    @Override
    public void applyDelegate(Config config) {
        Security.addProvider(new BouncyCastleProvider());
        if (isDebug()) {
            Configurator.setAllLevels("de.rub.nds.tlsattacker", Level.DEBUG);
        }
        LOGGER.debug("Using the following security providers");
        for (Provider p : Security.getProviders()) {
            LOGGER.debug("Provider {}, version, {}", p.getName(), p.getVersion());
        }

        // remove stupid Oracle JDK security restriction (otherwise, it is not
        // possible to use strong crypto with Oracle JDK)
        UnlimitedStrengthEnabler.enable();
    }
}
