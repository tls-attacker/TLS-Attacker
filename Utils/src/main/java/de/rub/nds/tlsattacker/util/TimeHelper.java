/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.util;

public class TimeHelper {
    private static TimeProvider provider;

    public static long getTime() {
        if (provider == null) {
            provider = new RealTimeProvider();
        }
        return provider.getTime();
    }

    public static void setProvider(TimeProvider provider) {
        TimeHelper.provider = provider;
    }

    private TimeHelper() {
    }

}
