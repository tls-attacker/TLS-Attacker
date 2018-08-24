/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.util;

public class Time {

    /**
     * Unix time means number of seconds since 1970, in GMT time zone.
     * Date.getTime() returns number of milliseconds since 1970 in GMT, thus we
     * convert it to seconds.
     * 
     * @return unix time
     */
    public static long getUnixTime() {

        // long millis = new Date().getTime();
        long sec = System.currentTimeMillis() / 1000;

        return sec;
    }

    private Time() {
    }
}
