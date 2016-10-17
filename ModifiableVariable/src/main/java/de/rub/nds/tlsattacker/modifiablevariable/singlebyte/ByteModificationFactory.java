/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable.singlebyte;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

import de.rub.nds.tlsattacker.modifiablevariable.FileConfigurationException;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.util.RandomHelper;

/**
 * @author
 */
final public class ByteModificationFactory {

    private static final int BYTE_EXPLICIT_VALUE_MODIFICATION = 3;

    private static final int BYTE_XOR_MODIFICATION = 2;

    private static final int BYTE_SUBTRACT_MODIFICATION = 1;

    private static final int BYTE_ADD_MODIFICATION = 0;

    private static final int MODIFICATION_COUNT = 5;
    
    private static List<VariableModification<Byte>> modificationsFromFile;

    public static final String FILE_NAME = "byte.vec";

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
    
    public static VariableModification<Byte> explicitValueFromFile(int value) {
        List<VariableModification<Byte>> modifications = modificationsFromFile();
        int pos = value % modifications.size();
        return modifications.get(pos);
    }

    public static synchronized List<VariableModification<Byte>> modificationsFromFile() {
        try {
            if (modificationsFromFile == null) {
                modificationsFromFile = new LinkedList<>();
                ClassLoader classLoader = ByteModificationFactory.class.getClassLoader();
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
            case 4:
                vm = explicitValueFromFile(random.nextInt(Byte.MAX_VALUE));
                return vm;
	}
	return vm;
    }

}
