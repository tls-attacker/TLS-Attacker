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
package de.rub.nds.tlsattacker.modifiablevariable.integer;

import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.util.RandomHelper;
import java.util.Random;

/**
 * @author
 */
final public class IntegerModificationFactory {

    private static final int MODIFICATION_COUNT = 4;

    private static final int MAX_MODIFICATION_VALUE = 32000;

    private IntegerModificationFactory() {
    }

    public static IntegerAddModification add(final String summand) {
	return add(new Integer(summand));
    }

    public static IntegerAddModification add(final Integer summand) {
	return new IntegerAddModification(summand);
    }

    public static VariableModification<Integer> sub(final String subtrahend) {
	return sub(new Integer(subtrahend));
    }

    public static VariableModification<Integer> sub(final Integer subtrahend) {
	return new IntegerSubtractModification(subtrahend);
    }

    public static VariableModification<Integer> xor(final String xor) {
	return xor(new Integer(xor));
    }

    public static VariableModification<Integer> xor(final Integer xor) {
	return new IntegerXorModification(xor);
    }

    public static VariableModification<Integer> explicitValue(final String value) {
	return explicitValue(new Integer(value));
    }

    public static VariableModification<Integer> explicitValue(final Integer value) {
	return new IntegerExplicitValueModification(value);
    }

    public static VariableModification<Integer> createRandomModification() {
	Random random = RandomHelper.getRandom();
	int r = random.nextInt(MODIFICATION_COUNT);
	int modification = random.nextInt(MAX_MODIFICATION_VALUE);
	VariableModification<Integer> vm = null;
	switch (r) {
	    case 0:
		vm = new IntegerAddModification(modification);
		return vm;
	    case 1:
		vm = new IntegerSubtractModification(modification);
		return vm;
	    case 2:
		vm = new IntegerXorModification(modification);
		return vm;
	    case 3:
		vm = new IntegerExplicitValueModification(modification);
		return vm;
	}
	return vm;
    }

}
