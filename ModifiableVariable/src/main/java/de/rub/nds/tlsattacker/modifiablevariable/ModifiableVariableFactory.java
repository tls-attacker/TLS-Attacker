/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
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

import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ModifiableVariableFactory {

    private ModifiableVariableFactory() {

    }

    public static ModifiableVariable<BigInteger> createBigIntegerModifiableVariable() {
	return new ModifiableVariable<>(BigInteger.class);
    }

    public static ModifiableVariable<Integer> createIntegerModifiableVariable() {
	return new ModifiableVariable<>(Integer.class);
    }

    public static ModifiableVariable<Byte> createByteModifiableVariable() {
	return new ModifiableVariable<>(Byte.class);
    }

    public static ModifiableVariable<byte[]> createByteArrayModifiableVariable() {
	return new ModifiableVariable<>(byte[].class);
    }

    public static ModifiableVariable<BigInteger> safelySetValue(ModifiableVariable<BigInteger> mv, BigInteger value) {
	if (mv == null) {
	    mv = new ModifiableVariable<>();
	}
	mv.setOriginalValue(value);
	return mv;
    }

    public static ModifiableVariable<Integer> safelySetValue(ModifiableVariable<Integer> mv, Integer value) {
	if (mv == null) {
	    mv = new ModifiableVariable<>();
	}
	mv.setOriginalValue(value);
	return mv;
    }

    public static ModifiableVariable<Byte> safelySetValue(ModifiableVariable<Byte> mv, Byte value) {
	if (mv == null) {
	    mv = new ModifiableVariable<>();
	}
	mv.setOriginalValue(value);
	return mv;
    }

    public static ModifiableVariable<byte[]> safelySetValue(ModifiableVariable<byte[]> mv, byte[] value) {
	if (mv == null) {
	    mv = new ModifiableVariable<>();
	}
	mv.setOriginalValue(value);
	return mv;
    }
}
