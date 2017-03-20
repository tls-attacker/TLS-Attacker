/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow;

import com.openpojo.reflection.PojoClass;
import com.openpojo.reflection.impl.PojoClassFactory;
import com.openpojo.validation.PojoValidator;
import com.openpojo.validation.Validator;
import com.openpojo.validation.ValidatorBuilder;
import com.openpojo.validation.rule.impl.GetterMustExistRule;
import com.openpojo.validation.rule.impl.SetterMustExistRule;
import com.openpojo.validation.test.impl.GetterTester;
import com.openpojo.validation.test.impl.SetterTester;
import org.junit.Before;
import org.junit.Test;

/**
 * TODO
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TlsConfigTest {

    public TlsConfigTest() {
    }

    // @Test
    // public void validateSettersAndGetters() {
    // PojoClass configPojo = PojoClassFactory.getPojoClass(TlsConfig.class);
    //
    // PojoValidator pojoValidator = new PojoValidator();
    //
    // // Lets make sure that we have a getter and a setter for every field
    // // defined.
    // pojoValidator.addRule(new SetterMustExistRule());
    // pojoValidator.addRule(new GetterMustExistRule());
    // SetterTester setterTester = new SetterTester();
    // GetterTester getterTester = new GetterTester();
    //
    // // Lets also validate that they are behaving as expected
    // pojoValidator.addTester(setterTester);
    // pojoValidator.addTester(getterTester);
    //
    // // Start the Test
    // pojoValidator.runValidation(configPojo);
    // }
}
