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

import static de.rub.nds.tlsattacker.util.ArrayConverter.bytesToHexString;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.util.ByteArrayAdapter;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
@XmlRootElement
@XmlType(propOrder = { "xor", "startPosition", "modificationFilter", "postModification" })
public class ByteArrayXorModification extends VariableModification<byte[]> {

    private byte[] xor;

    private int startPosition;

    public ByteArrayXorModification() {

    }

    public ByteArrayXorModification(byte[] xor, int startPosition) {
	this.xor = xor;
	this.startPosition = startPosition;
    }

    @Override
    protected byte[] modifyImplementationHook(final byte[] input) {
	byte[] result = input.clone();
	int start = startPosition;
	if (start < 0) {
	    start += input.length;
	}
	final int end = start + xor.length;
	if (end > result.length) {
	    // result = new byte[end];
	    // System.arraycopy(input, 0, result, 0, input.length);
	    throw new ArrayIndexOutOfBoundsException(String.format(
		    "Input {%s} of length %d cannot be xored with {%s} of length %d with start position %d",
		    bytesToHexString(input), input.length, bytesToHexString(xor), xor.length, startPosition));
	}
	for (int i = 0; i < xor.length; ++i) {
	    result[start + i] = (byte) (input[start + i] ^ xor[i]);
	}
	return result;
    }

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    public byte[] getXor() {
	return xor;
    }

    public void setXor(byte[] xor) {
	this.xor = xor;
    }

    public int getStartPosition() {
	return startPosition;
    }

    public void setStartPosition(int startPosition) {
	this.startPosition = startPosition;
    }
}
