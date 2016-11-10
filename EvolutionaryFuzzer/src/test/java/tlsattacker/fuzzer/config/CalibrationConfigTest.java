/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.config;

import com.openpojo.reflection.PojoClass;
import com.openpojo.reflection.impl.PojoClassFactory;
import com.openpojo.validation.PojoValidator;
import com.openpojo.validation.rule.impl.GetterMustExistRule;
import com.openpojo.validation.rule.impl.SetterMustExistRule;
import com.openpojo.validation.test.impl.GetterTester;
import com.openpojo.validation.test.impl.SetterTester;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author ic0ns
 */
public class CalibrationConfigTest {

    public CalibrationConfigTest() {
    }

    @Before
    public void setUp() {
    }

    @Test
    public void validateSettersAndGetters() {
        PojoClass pojoClass = PojoClassFactory.getPojoClass(CalibrationConfig.class);

        PojoValidator pojoValidator = new PojoValidator();

        // Lets also validate that they are behaving as expected
        pojoValidator.addTester(new SetterTester());
        pojoValidator.addTester(new GetterTester());

        // Start the Test
        pojoValidator.runValidation(pojoClass);
    }

}
