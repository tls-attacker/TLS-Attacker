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
import de.rub.nds.tlsattacker.transport.TransportHandlerType;

/**
 * Converts a transport handler type string to a TransportHandlerType value (for
 * command line purposes).
 */
public class TransportHandlerTypeConverter implements IStringConverter<TransportHandlerType> {

    @Override
    public TransportHandlerType convert(String value) {
        try {
            return TransportHandlerType.valueOf(value);
        } catch (IllegalArgumentException e) {
            throw new ParameterException("Value " + value + " cannot be converted to TransportHandlerType.");
        }
    }
}
