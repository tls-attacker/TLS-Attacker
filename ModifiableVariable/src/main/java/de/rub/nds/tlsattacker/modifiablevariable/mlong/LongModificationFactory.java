/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable.mlong;

import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.util.RandomHelper;
import java.util.Random;

/**
 * @author
 */
final public class LongModificationFactory {

    private static final int MODIFICATION_COUNT = 4;

    private static final int MAX_MODIFICATION_VALUE = 32000;

    private LongModificationFactory() {
    }

    public static LongAddModification add(final String summand) {
	return add(new Long(summand));
    }

    public static LongAddModification add(final Long summand) {
	return new LongAddModification(summand);
    }

    public static VariableModification<Long> sub(final String subtrahend) {
	return sub(new Long(subtrahend));
    }

    public static VariableModification<Long> sub(final Long subtrahend) {
	return new LongSubtractModification(subtrahend);
    }

    public static VariableModification<Long> xor(final String xor) {
	return xor(new Long(xor));
    }

    public static VariableModification<Long> xor(final Long xor) {
	return new LongXorModification(xor);
    }

    public static VariableModification<Long> explicitValue(final String value) {
	return explicitValue(new Long(value));
    }

    public static VariableModification<Long> explicitValue(final Long value) {
	return new LongExplicitValueModification(value);
    }

    public static VariableModification<Long> createRandomModification() {
	Random random = RandomHelper.getRandom();
	int r = random.nextInt(MODIFICATION_COUNT);
	long modification = random.nextInt(MAX_MODIFICATION_VALUE);
	VariableModification<Long> vm = null;
	switch (r) {
	    case 0:
		vm = new LongAddModification(modification);
		return vm;
	    case 1:
		vm = new LongSubtractModification(modification);
		return vm;
	    case 2:
		vm = new LongXorModification(modification);
		return vm;
	    case 3:
		vm = new LongExplicitValueModification(modification);
		return vm;
	}
	return vm;
    }

}
