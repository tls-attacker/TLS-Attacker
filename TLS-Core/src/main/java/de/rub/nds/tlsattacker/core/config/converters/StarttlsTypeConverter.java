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
import de.rub.nds.tlsattacker.core.constants.StarttlsType;

public class StarttlsTypeConverter implements IStringConverter<StarttlsType> {

    @Override
    public StarttlsType convert(String starttlsType) {
        starttlsType = starttlsType.toUpperCase();
        try {
            switch (starttlsType) {
                case "FTP": {
                    return StarttlsType.FTP;
                }
                case "IMAP": {
                    return StarttlsType.IMAP;
                }
                case "POP3": {
                    return StarttlsType.POP3;
                }
                case "SMTP": {
                    return StarttlsType.SMTP;
                }
            }
        } catch (IllegalArgumentException e) {
            throw new ParameterException("String " + starttlsType + " cannot be converted to a StarttlsType.");
        }
        return StarttlsType.NONE;
    }
}
