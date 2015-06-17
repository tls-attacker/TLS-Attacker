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
package de.rub.nds.tlsattacker.modifiablevariable.bytearray;

import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.util.RandomHelper;
import java.util.Random;

final public class ByteArrayModificationFactory {

    private static final int BYTE_ARRAY_EXPLICIT_VALUE_MODIFICATION = 3;

    private static final int BYTE_ARRAY_DELETE_MODIFICATION = 2;

    private static final int BYTE_ARRAY_INSERT_MODIFICATION = 1;

    private static final int BYTE_ARRAY_XOR_MODIFICATION = 0;

    private static final int MODIFICATION_COUNT = 4;

    private static final int MAX_BYTE_ARRAY_LENGTH = 200;

    private static final int MODIFIED_ARRAY_LENGTH_ESTIMATION = 50;

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

    public static VariableModification<byte[]> explicitValue(final byte[] explicitValue) {
	return new ByteArrayExplicitValueModification(explicitValue);
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
	    if (originalValue.length == 0) {
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
		modificationArrayLength = random.nextInt(MAX_BYTE_ARRAY_LENGTH);
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
		modificationArrayLength = random.nextInt(MAX_BYTE_ARRAY_LENGTH);
		byte[] explicitValue = new byte[modificationArrayLength];
		random.nextBytes(explicitValue);
		vm = new ByteArrayExplicitValueModification(explicitValue);
		return vm;
	}
	return vm;
    }

}
