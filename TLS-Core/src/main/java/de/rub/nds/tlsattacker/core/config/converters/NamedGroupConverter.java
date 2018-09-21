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
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.util.Arrays;

/**
 * Converts a string named group to a NamedGroup type (for command line
 * purposes).
 */
public class NamedGroupConverter implements IStringConverter<NamedGroup> {

    @Override
    public NamedGroup convert(String value) {

        try {
            return NamedGroup.valueOf(value);
        } catch (IllegalArgumentException e) {
            throw new ParameterException("Value " + value + " cannot be converted to a NamedGroup. "
                    + "Available values are: " + Arrays.toString(NamedGroup.values()));
        }
    }
}
