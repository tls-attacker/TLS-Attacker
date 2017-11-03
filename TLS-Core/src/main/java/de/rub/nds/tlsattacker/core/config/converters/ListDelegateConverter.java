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
import de.rub.nds.tlsattacker.core.constants.ListDelegateType;

/**
 * Converts a list delegate type string to a ListDeleagteType value.
 */
public class ListDelegateConverter implements IStringConverter<ListDelegateType> {

    @Override
    public ListDelegateType convert(String value) {
        try {
            return ListDelegateType.valueOf(value);
        } catch (IllegalArgumentException e) {
            throw new ParameterException("Value " + value + " is not a supported by -list");
        }
    }
}
