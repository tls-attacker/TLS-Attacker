/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import com.openpojo.validation.Validator;
import com.openpojo.validation.ValidatorBuilder;
import com.openpojo.validation.test.impl.GetterTester;
import com.openpojo.validation.test.impl.SetterTester;
import org.junit.Test;

public class PojoPackageTest {

    // The package to be tested
    private final String packageName = "de.rub.nds.tlsattacker.core.protocol.message";

    @Test
    public void validate() {
        Validator validator = ValidatorBuilder.create().with(new SetterTester(), new GetterTester()).build();
        validator.validate(packageName);
    }
}
