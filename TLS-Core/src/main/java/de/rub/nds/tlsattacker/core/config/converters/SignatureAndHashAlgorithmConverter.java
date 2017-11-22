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
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;

public class SignatureAndHashAlgorithmConverter implements IStringConverter<SignatureAndHashAlgorithm> {

    @Override
    public SignatureAndHashAlgorithm convert(String value) {
        try {
            String[] split = value.split("-");
            if (split.length != 2) {
                throw new ParameterException("Value " + value
                        + " cannot be converted to a Signature and Hash algorithm.");
            }
            SignatureAndHashAlgorithm algo = new SignatureAndHashAlgorithm(SignatureAlgorithm.valueOf(split[0]),
                    HashAlgorithm.valueOf(split[1]));
            return algo;
        } catch (IllegalArgumentException e) {
            throw new ParameterException("Value " + value + " cannot be converted to a Signature and Hash algorithm. ");
        }
    }

}
