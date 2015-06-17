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
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import java.math.BigInteger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ModifiableVariableFactory {

    private ModifiableVariableFactory() {

    }

    public static ModifiableBigInteger createBigIntegerModifiableVariable() {
	return new ModifiableBigInteger();
    }

    public static ModifiableInteger createIntegerModifiableVariable() {
	return new ModifiableInteger();
    }

    public static ModifiableByte createByteModifiableVariable() {
	return new ModifiableByte();
    }

    public static ModifiableByteArray createByteArrayModifiableVariable() {
	return new ModifiableByteArray();
    }

    public static ModifiableBigInteger safelySetValue(ModifiableBigInteger mv, BigInteger value) {
	if (mv == null) {
	    mv = new ModifiableBigInteger();
	}
	mv.setOriginalValue(value);
	return mv;
    }

    public static ModifiableInteger safelySetValue(ModifiableInteger mv, Integer value) {
	if (mv == null) {
	    mv = new ModifiableInteger();
	}
	mv.setOriginalValue(value);
	return mv;
    }

    public static ModifiableByte safelySetValue(ModifiableByte mv, Byte value) {
	if (mv == null) {
	    mv = new ModifiableByte();
	}
	mv.setOriginalValue(value);
	return mv;
    }

    public static ModifiableByteArray safelySetValue(ModifiableByteArray mv, byte[] value) {
	if (mv == null) {
	    mv = new ModifiableByteArray();
	}
	mv.setOriginalValue(value);
	return mv;
    }
}
