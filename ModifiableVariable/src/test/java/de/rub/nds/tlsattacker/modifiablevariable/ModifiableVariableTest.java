/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.modifiablevariable;

import de.rub.nds.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.math.BigInteger;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ModifiableVariableTest {

    @Test
    public void testRandomBigIntegerModification() {
	ModifiableBigInteger bigInteger = ModifiableVariableFactory.createBigIntegerModifiableVariable();
	bigInteger.setOriginalValue(BigInteger.ZERO);
	bigInteger.createRandomModificationAtRuntime();
	System.out.println("Randomly modified big integer: " + bigInteger.getValue());
	assertNotNull(bigInteger.getModification());
    }

    @Test
    public void testRandomIntegerModification() {
	ModifiableInteger integer = ModifiableVariableFactory.createIntegerModifiableVariable();
	integer.setOriginalValue(0);
	integer.createRandomModificationAtRuntime();
	System.out.println("Randomly modified integer: " + integer.getValue());
	assertNotNull(integer.getModification());
    }

    @Test
    public void testRandomByteArrayModification() {
	ModifiableByteArray array = ModifiableVariableFactory.createByteArrayModifiableVariable();
	array.setOriginalValue(new byte[] { 0, 1, 2 });
	array.createRandomModificationAtRuntime();
	System.out.println("Randomly modified byte array: " + ArrayConverter.bytesToHexString(array.getValue()));
	assertNotNull(array.getModification());
    }
}
