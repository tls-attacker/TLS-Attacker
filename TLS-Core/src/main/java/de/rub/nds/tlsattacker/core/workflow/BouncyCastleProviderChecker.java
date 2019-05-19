/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import java.security.Provider;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BouncyCastleProviderChecker {

    static boolean isLoaded() {
        for (Provider p : Security.getProviders()) {
            if (p.getClass().equals(BouncyCastleProvider.class)) {
                return true;
            }
        }
        return false;
    }
}
