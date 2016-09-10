/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable.bytearray;

import de.rub.nds.tlsattacker.modifiablevariable.FileConfigurationException;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.RandomHelper;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

final public class ByteArrayModificationFactory {

    private static final int BYTE_ARRAY_SHUFFLE_MODIFICATION = 6;

    private static final int BYTE_ARRAY_EXPLICIT_VALUE_MODIFICATION_FROM_FILE = 5;

    private static final int BYTE_ARRAY_DUPLICATE_MODIFICATION = 4;

    private static final int BYTE_ARRAY_EXPLICIT_VALUE_MODIFICATION = 3;

    private static final int BYTE_ARRAY_DELETE_MODIFICATION = 2;

    private static final int BYTE_ARRAY_INSERT_MODIFICATION = 1;

    private static final int BYTE_ARRAY_XOR_MODIFICATION = 0;

    private static final int MODIFICATION_COUNT = 7;

    private static final int MAX_CONFIG_PARAMETER = 200;

    private static final int EXPLICIT_VALUE_RANDOM = 1000;

    private static final int MODIFIED_ARRAY_LENGTH_ESTIMATION = 50;

    private static List<VariableModification<byte[]>> modificationsFromFile;

    public static final String FILE_NAME = "de/rub/nds/tlsattacker/explicit/array.vec";

    private ByteArrayModificationFactory() {
    }

    /**
     * *
     * 
     * @param xor
     *            bytes to xor
     * @param startPosition
     *            , negative numbers mean that the position is taken from the
     *            end
     * @return
     */
    public static VariableModification<byte[]> xor(final byte[] xor, final int startPosition) {
	return new ByteArrayXorModification(xor, startPosition);
    }

    /**
     * *
     * 
     * @param bytesToInsert
     *            bytes to xor
     * @param startPosition
     *            , negative numbers mean that the position is taken from the
     *            end
     * @return
     */
    public static VariableModification<byte[]> insert(final byte[] bytesToInsert, final int startPosition) {
	return new ByteArrayInsertModification(bytesToInsert, startPosition);
    }

    /**
     * * Deletes $count bytes from the input array beginning at $startPosition
     * 
     * @param startPosition
     *            , negative numbers mean that the position is taken from the
     *            end
     * @param count
     * @return
     */
    public static VariableModification<byte[]> delete(final int startPosition, final int count) {
	return new ByteArrayDeleteModification(startPosition, count);
    }

    /**
     * Duplicates the byte array
     * 
     * @return
     */
    public static VariableModification<byte[]> duplicate() {
	return new ByteArrayDuplicateModification();
    }

    public static VariableModification<byte[]> explicitValue(final byte[] explicitValue) {
	return new ByteArrayExplicitValueModification(explicitValue);
    }

    public static VariableModification<byte[]> explicitValueFromFile(int value) {
	List<VariableModification<byte[]>> modifications = modificationsFromFile();
	int pos = value % modifications.size();
	return modifications.get(pos);
    }

    /**
     * Shuffles the bytes in the array, given a specified array of positions.
     * 
     * @param shuffle
     * @return
     */
    public static VariableModification<byte[]> shuffle(final byte[] shuffle) {
	return new ByteArrayShuffleModification(shuffle);
    }

    public static List<VariableModification<byte[]>> modificationsFromFile() {
	try {
	    if (modificationsFromFile == null) {
		modificationsFromFile = new LinkedList<>();
		ClassLoader classLoader = ByteArrayModificationFactory.class.getClassLoader();
		InputStream is = classLoader.getResourceAsStream(FILE_NAME);
		BufferedReader br = new BufferedReader(new InputStreamReader(is));
		String line;
		while ((line = br.readLine()) != null) {
		    line = line.replaceAll("\\s+", "");
		    byte[] value = ArrayConverter.hexStringToByteArray(line);
		    modificationsFromFile.add(explicitValue(value));
		}
	    }
	    return modificationsFromFile;
	} catch (IOException ex) {
	    throw new FileConfigurationException("Modifiable variable file name could not have been found.", ex);
	}
    }

    public static VariableModification<byte[]> createRandomModification(byte[] originalValue) {
	Random random = RandomHelper.getRandom();
	int r = random.nextInt(MODIFICATION_COUNT);
	VariableModification<byte[]> vm = null;
	int modifiedArrayLength;
	if (originalValue == null) {
	    modifiedArrayLength = MODIFIED_ARRAY_LENGTH_ESTIMATION;
	} else {
	    modifiedArrayLength = originalValue.length;
	    if (originalValue.length == 0 || originalValue.length == 1) {
		r = BYTE_ARRAY_EXPLICIT_VALUE_MODIFICATION;
	    }
	}
	switch (r) {
	    case BYTE_ARRAY_XOR_MODIFICATION:
		int modificationArrayLength = random.nextInt(modifiedArrayLength);
		byte[] xor = new byte[modificationArrayLength];
		random.nextBytes(xor);
		int startPosition = random.nextInt(modifiedArrayLength - modificationArrayLength);
		vm = new ByteArrayXorModification(xor, startPosition);
		return vm;
	    case BYTE_ARRAY_INSERT_MODIFICATION:
		modificationArrayLength = random.nextInt(MAX_CONFIG_PARAMETER);
		byte[] bytesToInsert = new byte[modificationArrayLength];
		random.nextBytes(bytesToInsert);
		int insertPosition = random.nextInt(modifiedArrayLength);
		vm = new ByteArrayInsertModification(bytesToInsert, insertPosition);
		return vm;
	    case BYTE_ARRAY_DELETE_MODIFICATION:
		startPosition = random.nextInt(modifiedArrayLength - 1);
		int count = random.nextInt(modifiedArrayLength - startPosition);
		count++;
		vm = new ByteArrayDeleteModification(startPosition, count);
		return vm;
	    case BYTE_ARRAY_EXPLICIT_VALUE_MODIFICATION:
		modificationArrayLength = random.nextInt(MAX_CONFIG_PARAMETER);
		byte[] explicitValue = new byte[modificationArrayLength];
		random.nextBytes(explicitValue);
		vm = new ByteArrayExplicitValueModification(explicitValue);
		return vm;
	    case BYTE_ARRAY_DUPLICATE_MODIFICATION:
		vm = new ByteArrayDuplicateModification();
		return vm;
	    case BYTE_ARRAY_EXPLICIT_VALUE_MODIFICATION_FROM_FILE:
		vm = explicitValueFromFile(random.nextInt(EXPLICIT_VALUE_RANDOM));
		return vm;
	    case BYTE_ARRAY_SHUFFLE_MODIFICATION:
		int shuffleSize = random.nextInt(MAX_CONFIG_PARAMETER);
		byte[] shuffle = new byte[shuffleSize];
		random.nextBytes(shuffle);
		vm = shuffle(shuffle);
		return vm;
	}
	return vm;
    }

}
