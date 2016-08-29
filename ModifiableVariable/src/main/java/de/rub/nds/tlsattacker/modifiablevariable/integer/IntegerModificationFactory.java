/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable.integer;

import de.rub.nds.tlsattacker.modifiablevariable.FileConfigurationException;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.util.RandomHelper;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

/**
 * @author
 */
final public class IntegerModificationFactory {

    private static final int MODIFICATION_COUNT = 7;

    private static final int MAX_MODIFICATION_VALUE = 32000;

    private static final int MAX_MODIFICATION_SHIFT_VALUE = 20;

    private static List<VariableModification<Integer>> modificationsFromFile;

    public static final String FILE_NAME = "integer.vec";

    private IntegerModificationFactory() {
    }

    public static IntegerAddModification add(final String summand) {
	return add(new Integer(summand));
    }

    public static IntegerAddModification add(final Integer summand) {
	return new IntegerAddModification(summand);
    }

    public static IntegerShiftLeftModification shiftLeft(final String shift) {
	return shiftLeft(new Integer(shift));
    }

    public static IntegerShiftLeftModification shiftLeft(final Integer shift) {
	return new IntegerShiftLeftModification(shift);
    }

    public static IntegerShiftRightModification shiftRight(final String shift) {
	return shiftRight(new Integer(shift));
    }

    public static IntegerShiftRightModification shiftRight(final Integer shift) {
	return new IntegerShiftRightModification(shift);
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

    public static VariableModification<Integer> explicitValueFromFile(int value) {
	List<VariableModification<Integer>> modifications = modificationsFromFile();
	int pos = value % modifications.size();
	return modifications.get(pos);
    }

    public static List<VariableModification<Integer>> modificationsFromFile() {
	try {
	    if (modificationsFromFile == null) {
		modificationsFromFile = new LinkedList<>();
		ClassLoader classLoader = IntegerModificationFactory.class.getClassLoader();
		InputStream is = classLoader.getResourceAsStream(FILE_NAME);
		BufferedReader br = new BufferedReader(new InputStreamReader(is));
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

    public static VariableModification<Integer> createRandomModification() {
	Random random = RandomHelper.getRandom();
	int r = random.nextInt(MODIFICATION_COUNT);
	int modification = random.nextInt(MAX_MODIFICATION_VALUE);
	int shiftModification = random.nextInt(MAX_MODIFICATION_SHIFT_VALUE);
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
	    case 4:
		vm = new IntegerShiftLeftModification(shiftModification);
		return vm;
	    case 5:
		vm = new IntegerShiftRightModification(shiftModification);
		return vm;
	    case 6:
		vm = explicitValueFromFile(random.nextInt(MAX_MODIFICATION_VALUE));
		return vm;
	}
	return vm;
    }

}
