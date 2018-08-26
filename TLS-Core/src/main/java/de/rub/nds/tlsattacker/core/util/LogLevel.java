/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.util;

import org.apache.logging.log4j.Level;

public class LogLevel {

    /**
     * This log level is used to inform about important results of TLS
     * evaluations. For example, to present a final result of an executed
     * attack.
     */
    public static final Level DIRECT = Level.forName("Direct", 150);

    private LogLevel() {
    }
}
