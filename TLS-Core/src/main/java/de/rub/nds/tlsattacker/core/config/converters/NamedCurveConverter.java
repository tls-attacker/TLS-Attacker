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
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import java.util.Arrays;

/**
 * Converts a string named curve to a NamedCurve type (for command line
 * purposes).
 * 

 */
public class NamedCurveConverter implements IStringConverter<NamedCurve> {

    @Override
    public NamedCurve convert(String value) {

        try {
            return NamedCurve.valueOf(value);
        } catch (IllegalArgumentException e) {
            throw new ParameterException("Value " + value + " cannot be converted to a NamedCurve. "
                    + "Available values are: " + Arrays.toString(NamedCurve.values()));
        }
    }
}
