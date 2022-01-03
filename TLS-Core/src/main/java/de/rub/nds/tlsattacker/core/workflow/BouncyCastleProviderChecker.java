/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow;

import java.security.Provider;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BouncyCastleProviderChecker {

    static boolean isLoaded() {
        for (Provider p : Security.getProviders()) {
            if (p.getClass().getName().equals(BouncyCastleProvider.class.getName())) {
                return true;
            }
        }
        return false;
    }
}
