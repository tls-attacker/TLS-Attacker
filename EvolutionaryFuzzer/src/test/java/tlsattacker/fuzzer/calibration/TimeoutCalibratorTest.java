/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.calibration;

import com.openpojo.reflection.PojoClass;
import com.openpojo.reflection.impl.PojoClassFactory;
import com.openpojo.validation.PojoValidator;
import com.openpojo.validation.test.impl.GetterTester;
import com.openpojo.validation.test.impl.SetterTester;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TimeoutCalibratorTest {

    public TimeoutCalibratorTest() {
    }

    @Before
    public void setUp() {
    }

    @Test
    public void validateSettersAndGetters() {
        PojoClass pojoClass = PojoClassFactory.getPojoClass(TimeoutCalibrator.class);

        PojoValidator pojoValidator = new PojoValidator();

        // Lets also validate that they are behaving as expected
        pojoValidator.addTester(new SetterTester());
        pojoValidator.addTester(new GetterTester());

        // Start the Test
        pojoValidator.runValidation(pojoClass);
    }

    /**
     * Test of calibrateTimeout method, of class TimeoutCalibrator.
     */
    @Test
    public void testCalibrateTimeout() {
    }

    /**
     * Test of testCiphersuite method, of class TimeoutCalibrator.
     */
    @Test
    public void testTestCiphersuite() {
    }

}
