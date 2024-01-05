/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.util;

import java.security.Security;
import java.util.Arrays;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ProviderUtil {
    /**
     * Adds the BouncyCastleProvider only when not already registered. Saves time otherwise spend on
     * multiple instantiations during Config initialization.
     */
    public static void addBouncyCastleProvider() {
        if (Arrays.stream(Security.getProviders())
                .noneMatch(x -> x instanceof BouncyCastleProvider)) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
