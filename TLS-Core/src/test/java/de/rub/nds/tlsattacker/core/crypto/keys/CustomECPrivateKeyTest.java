/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.keys;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.math.BigInteger;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.List;
import org.junit.Assert;
import static org.junit.Assert.assertNotNull;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ErrorCollector;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class CustomECPrivateKeyTest {

    @Parameter(0)
    public NamedGroup curve;

    @Rule
    public ErrorCollector collector = new ErrorCollector();

    @Parameters
    public static Iterable<Object[]> createParameters() {
        List<Object[]> testValues = new ArrayList<>();
        for (NamedGroup curve : NamedGroup.getImplemented()) {
            if (curve.isStandardCurve()) {
                testValues.add(new Object[] { curve });
            }
        }
        return testValues;
    }

    /**
     * Test of getParams method, of class CustomECPrivateKey.
     */
    @Test
    public void testGetParams() {
        CustomECPrivateKey key = new CustomECPrivateKey(BigInteger.TEN, curve);
        ECParameterSpec params = key.getParams();
        System.out.println("Supported: " + curve.name());
        assertNotNull(params);
    }
}
