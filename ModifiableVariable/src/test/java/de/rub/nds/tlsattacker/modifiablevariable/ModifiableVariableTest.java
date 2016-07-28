/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable;

import de.rub.nds.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ModifiableVariableTest {
    
    private static final Logger LOGGER = LogManager.getLogger(ModifiableVariableTest.class);

    @Test
    public void testRandomBigIntegerModification() {
	ModifiableBigInteger bigInteger = ModifiableVariableFactory.createBigIntegerModifiableVariable();
	bigInteger.setOriginalValue(BigInteger.ZERO);
	bigInteger.createRandomModificationAtRuntime();
	LOGGER.info("Randomly modified big integer: " + bigInteger.getValue());
	assertNotNull(bigInteger.getModification());
    }

    @Test
    public void testRandomIntegerModification() {
	ModifiableInteger integer = ModifiableVariableFactory.createIntegerModifiableVariable();
	integer.setOriginalValue(0);
	integer.createRandomModificationAtRuntime();
	LOGGER.info("Randomly modified integer: " + integer.getValue());
	assertNotNull(integer.getModification());
    }

    @Test
    public void testRandomByteArrayModification() throws Exception {
	ModifiableByteArray array = ModifiableVariableFactory.createByteArrayModifiableVariable();
	array.setOriginalValue(new byte[] { 0, 1, 2 });
	array.createRandomModificationAtRuntime();
	LOGGER.info("Randomly modified byte array: " + ArrayConverter.bytesToHexString(array.getValue()));
	assertNotNull(array.getModification());
    }
}
