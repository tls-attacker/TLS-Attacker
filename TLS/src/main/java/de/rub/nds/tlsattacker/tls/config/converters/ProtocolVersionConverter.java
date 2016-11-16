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
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;

/**
 * Converts a protocol version string to a protocol Version enum (for command
 * line purposes).
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ProtocolVersionConverter implements IStringConverter<ProtocolVersion> {

    @Override
    public ProtocolVersion convert(String value) {
        try {
            return ProtocolVersion.fromString(value);
        } catch (IllegalArgumentException ex) {
            throw new ParameterException(ex);
        }
    }
}
