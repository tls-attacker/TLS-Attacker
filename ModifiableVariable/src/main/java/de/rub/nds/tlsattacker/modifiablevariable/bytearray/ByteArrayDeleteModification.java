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
package de.rub.nds.tlsattacker.modifiablevariable.bytearray;

import de.rub.nds.tlsattacker.util.ArrayConverter;
import static de.rub.nds.tlsattacker.util.ArrayConverter.bytesToHexString;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import java.util.Arrays;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author juraj
 */
@XmlRootElement
public class ByteArrayDeleteModification extends VariableModification<byte[]> {

    private int count;

    private int startPosition;

    public ByteArrayDeleteModification() {

    }

    public ByteArrayDeleteModification(int startPosition, int count) {
	this.startPosition = startPosition;
	this.count = count;
    }

    @Override
    protected byte[] modifyImplementationHook(final byte[] input) {
	int start = startPosition;
	if (start < 0) {
	    start += input.length;
	}
	final int endPosition = start + count;
	if ((endPosition) > input.length) {
	    throw new ArrayIndexOutOfBoundsException(String.format(
		    "Bytes %d..%d cannot be deleted from {%s} of length %d", start, endPosition,
		    bytesToHexString(input), input.length));
	}
	if (count <= 0) {
	    throw new IllegalArgumentException("You must delete at least one byte. count = " + count);
	}
	byte[] ret1 = Arrays.copyOf(input, start);
	byte[] ret2 = null;
	if ((endPosition) < input.length) {
	    ret2 = Arrays.copyOfRange(input, endPosition, input.length);
	}
	return ArrayConverter.concatenate(ret1, ret2);
    }

    public int getStartPosition() {
	return startPosition;
    }

    public void setStartPosition(int startPosition) {
	this.startPosition = startPosition;
    }

    public int getCount() {
	return count;
    }

    public void setCount(int count) {
	this.count = count;
    }
}
