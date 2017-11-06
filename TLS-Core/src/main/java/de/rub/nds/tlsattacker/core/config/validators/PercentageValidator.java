/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.validators;

import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.ParameterException;

public class PercentageValidator implements IParameterValidator {
    @Override
    public void validate(String name, String value) throws ParameterException {
        int n = Integer.parseInt(value);
        if (n < 0 || n > 100) {
            throw new ParameterException("Parameter " + name + " should be between 0 and 100 (found " + value + ")");
        }
    }
}
