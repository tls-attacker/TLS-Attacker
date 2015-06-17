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
package de.rub.nds.tlsattacker.modifiablevariable.singlebyte;

import de.rub.nds.tlsattacker.modifiablevariable.integer.*;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.util.RandomHelper;
import java.util.Random;

/**
 * @author
 */
final public class ByteModificationFactory {

    private static final int BYTE_EXPLICIT_VALUE_MODIFICATION = 3;

    private static final int BYTE_XOR_MODIFICATION = 2;

    private static final int BYTE_SUBTRACT_MODIFICATION = 1;

    private static final int BYTE_ADD_MODIFICATION = 0;

    private static final int MODIFICATION_COUNT = 4;

    private ByteModificationFactory() {
    }

    public static ByteAddModification add(final String summand) {
	return add(new Byte(summand));
    }

    public static ByteAddModification add(final Byte summand) {
	return new ByteAddModification(summand);
    }

    public static VariableModification<Byte> sub(final String subtrahend) {
	return sub(new Byte(subtrahend));
    }

    public static VariableModification<Byte> sub(final Byte subtrahend) {
	return new ByteSubtractModification(subtrahend);
    }

    public static VariableModification<Byte> xor(final String xor) {
	return xor(new Byte(xor));
    }

    public static VariableModification<Byte> xor(final Byte xor) {
	return new ByteXorModification(xor);
    }

    public static VariableModification<Byte> explicitValue(final String value) {
	return explicitValue(new Byte(value));
    }

    public static VariableModification<Byte> explicitValue(final Byte value) {
	return new ByteExplicitValueModification(value);
    }

    public static VariableModification<Byte> createRandomModification() {
	Random random = RandomHelper.getRandom();
	int r = random.nextInt(MODIFICATION_COUNT);
	byte modification = (byte) random.nextInt(Byte.MAX_VALUE);
	VariableModification<Byte> vm = null;
	switch (r) {
	    case BYTE_ADD_MODIFICATION:
		vm = new ByteAddModification(modification);
		return vm;
	    case BYTE_SUBTRACT_MODIFICATION:
		vm = new ByteSubtractModification(modification);
		return vm;
	    case BYTE_XOR_MODIFICATION:
		vm = new ByteXorModification(modification);
		return vm;
	    case BYTE_EXPLICIT_VALUE_MODIFICATION:
		vm = new ByteExplicitValueModification(modification);
		return vm;
	}
	return vm;
    }

}
