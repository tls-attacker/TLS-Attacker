/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message.extension;

import com.openpojo.validation.Validator;
import com.openpojo.validation.ValidatorBuilder;
import com.openpojo.validation.test.impl.GetterTester;
import com.openpojo.validation.test.impl.SetterTester;
import org.junit.Test;

public class PojoPackageTest {

    // The package to be tested
    private final static String packageName = "de.rub.nds.tlsattacker.core.protocol.message.extension";

    @Test
    public void validate() {
        Validator validator = ValidatorBuilder.create().with(new SetterTester(), new GetterTester()).build();
        validator.validate(packageName);
    }
}
