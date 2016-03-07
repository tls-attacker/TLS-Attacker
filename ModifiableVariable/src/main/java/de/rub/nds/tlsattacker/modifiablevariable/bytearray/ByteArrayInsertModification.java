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

import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import static de.rub.nds.tlsattacker.util.ArrayConverter.bytesToHexString;
import de.rub.nds.tlsattacker.util.ByteArrayAdapter;
import java.util.Arrays;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
@XmlRootElement
@XmlType(propOrder = { "bytesToInsert", "startPosition", "modificationFilter", "postModification" })
public class ByteArrayInsertModification extends VariableModification<byte[]> {

    private byte[] bytesToInsert;

    private int startPosition;

    public ByteArrayInsertModification() {

    }

    public ByteArrayInsertModification(byte[] bytesToInsert, int startPosition) {
	this.bytesToInsert = bytesToInsert;
	this.startPosition = startPosition;
    }

    @Override
    protected byte[] modifyImplementationHook(final byte[] input) {
	byte[] result = input.clone();
	int start = startPosition;
	if (start < 0) {
	    start += input.length;
            if (start < 0) {
                //Man könnte auch versuchen die Startposition Modulo zu rechnen, aber vermutlich ist mehr schief gelaufen.
                throw new IllegalArgumentException("Trying to insert from too negative Startposition. start = " + startPosition);
            }
	}
        if (startPosition > input.length) {
	    throw new ArrayIndexOutOfBoundsException("Trying to insert behind the Array. ArraySize:"+ input.length + " Insert Position:" + startPosition);
	}
	byte[] ret1 = Arrays.copyOf(input, start);
	byte[] ret3 = null;
	if ((start) < input.length) {
	    ret3 = Arrays.copyOfRange(input, start, input.length);
	}
	return ArrayConverter.concatenate(ret1, bytesToInsert, ret3);
    }

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    public byte[] getBytesToInsert() {
	return bytesToInsert;
    }

    public void setBytesToInsert(byte[] bytesToInsert) {
	this.bytesToInsert = bytesToInsert;
    }

    public int getStartPosition() {
	return startPosition;
    }

    public void setStartPosition(int startPosition) {
	this.startPosition = startPosition;
    }
}
