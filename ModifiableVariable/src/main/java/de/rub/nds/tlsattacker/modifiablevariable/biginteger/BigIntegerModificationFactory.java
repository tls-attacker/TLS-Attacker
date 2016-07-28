/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable.biginteger;

import de.rub.nds.tlsattacker.modifiablevariable.FileConfigurationException;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.modifiablevariable.integer.IntegerModificationFactory;
import de.rub.nds.tlsattacker.util.RandomHelper;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

/**
 * @author
 */
final public class BigIntegerModificationFactory {

    private static final int MODIFICATION_COUNT = 7;

    private static final int MAX_MODIFICATION_VALUE = 320000;

    private static final int MAX_MODIFICATION_SHIFT_VALUE = 50;
    
    private static List<VariableModification<BigInteger>> modificationsFromFile;

    private BigIntegerModificationFactory() {
    }

    public static BigIntegerAddModification add(final String summand) {
	return add(new BigInteger(summand));
    }

    public static BigIntegerAddModification add(final BigInteger summand) {
	return new BigIntegerAddModification(summand);
    }

    public static BigIntegerShiftLeftModification shiftLeft(final String shift) {
	return shiftLeft(new Integer(shift));
    }

    public static BigIntegerShiftLeftModification shiftLeft(final Integer shift) {
	return new BigIntegerShiftLeftModification(shift);
    }

    public static BigIntegerShiftRightModification shiftRight(final String shift) {
	return shiftRight(new Integer(shift));
    }

    public static BigIntegerShiftRightModification shiftRight(final Integer shift) {
	return new BigIntegerShiftRightModification(shift);
    }

    public static VariableModification<BigInteger> sub(final String subtrahend) {
	return sub(new BigInteger(subtrahend));
    }

    public static VariableModification<BigInteger> sub(final BigInteger subtrahend) {
	return new BigIntegerSubtractModification(subtrahend);
    }

    public static VariableModification<BigInteger> xor(final String xor) {
	return xor(new BigInteger(xor));
    }

    public static VariableModification<BigInteger> xor(final BigInteger xor) {
	return new BigIntegerXorModification(xor);
    }

    public static VariableModification<BigInteger> explicitValue(final String value) {
	return explicitValue(new BigInteger(value));
    }

    public static VariableModification<BigInteger> explicitValue(final BigInteger value) {
	return new BigIntegerExplicitValueModification(value);
    }
    
    public static VariableModification<BigInteger> explicitValueFromFile(int value) {
        List<VariableModification<BigInteger>> modifications = modificationsFromFile();
        int pos = value % modifications.size();
        return modifications.get(pos);
    }

    public static List<VariableModification<BigInteger>> modificationsFromFile() {
        try {
            if (modificationsFromFile == null) {
                modificationsFromFile = new LinkedList<>();
                ClassLoader classLoader = IntegerModificationFactory.class.getClassLoader();
                File file = new File(classLoader.getResource(IntegerModificationFactory.FILE_NAME).getFile());
                BufferedReader br = new BufferedReader(new FileReader(file));
                String line;
                while ((line = br.readLine()) != null) {
                    String value = line.trim().split(" ")[0];
                    modificationsFromFile.add(explicitValue(value));
                }
            }
            return modificationsFromFile;
        } catch (IOException ex) {
            throw new FileConfigurationException("Modifiable variable file name could not have been found.", ex);
        }
    }

    public static VariableModification<BigInteger> createRandomModification() {
	Random random = RandomHelper.getRandom();
	int r = random.nextInt(MODIFICATION_COUNT);
	BigInteger modification = BigInteger.valueOf(random.nextInt(MAX_MODIFICATION_VALUE));
	int shiftModification = random.nextInt(MAX_MODIFICATION_SHIFT_VALUE);
	VariableModification<BigInteger> vm = null;
	switch (r) {
	    case 0:
		vm = new BigIntegerAddModification(modification);
		return vm;
	    case 1:
		vm = new BigIntegerSubtractModification(modification);
		return vm;
	    case 2:
		vm = new BigIntegerXorModification(modification);
		return vm;
	    case 3:
		vm = new BigIntegerExplicitValueModification(modification);
		return vm;
	    case 4:
		vm = new BigIntegerShiftLeftModification(shiftModification);
		return vm;
	    case 5:
		vm = new BigIntegerShiftRightModification(shiftModification);
		return vm;
            case 6:
                vm = explicitValueFromFile(MAX_MODIFICATION_VALUE);
                return vm;
	}
	return vm;
    }
}
