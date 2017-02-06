/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.config.converters;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.util.ArrayConverter;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
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
