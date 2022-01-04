/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.config.converters;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.ParameterException;
import java.math.BigInteger;

/**
 * Converts a string to a BigInteger. If the string starts with '0x', the value is considered to be hexadecimal (for
 * command line purposes).
 */
public class BigIntegerConverter implements IStringConverter<BigInteger> {

    @Override
    public BigInteger convert(String value) {

        try {
            if (value.startsWith("0x")) {
                return new BigInteger(value.substring(2), 16);
            } else {
                return new BigInteger(value);
            }
        } catch (IllegalArgumentException e) {
            throw new ParameterException("Value " + value + " cannot be converted to a BigInteger. "
                + "The value can be hexadecimal (starting with 0x) or decimal.");
        }
    }
}
