/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.converters;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.ParameterException;
import de.rub.nds.modifiablevariable.util.ArrayConverter;

public class ByteArrayConverter implements IStringConverter<byte[]> {

    @Override
    public byte[] convert(String value) {

        try {
            return ArrayConverter.hexStringToByteArray(value);
        } catch (IllegalArgumentException ex) {
            throw new ParameterException("Could not parse " + value + ". Not a hex String");
        }
    }
}
