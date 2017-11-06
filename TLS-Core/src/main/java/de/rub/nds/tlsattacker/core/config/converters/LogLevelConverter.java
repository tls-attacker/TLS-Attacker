/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.converters;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.ParameterException;
import java.util.Arrays;
import org.apache.logging.log4j.Level;

/**
 * Converts a log level string to an Apache log4j Level object (for command line
 * purposes).
 */
public class LogLevelConverter implements IStringConverter<Level> {

    @Override
    public Level convert(String value) {
        Level l = Level.toLevel(value);
        if (l == null) {
            throw new ParameterException("Value " + value + " cannot be converted to a log4j level. "
                    + "Available values are: " + Arrays.toString(Level.values()));
        }

        return l;
    }
}
