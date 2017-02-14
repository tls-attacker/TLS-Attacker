/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable.bytearray;

import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import static de.rub.nds.tlsattacker.util.ArrayConverter.bytesToHexString;
import java.util.Arrays;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
@XmlRootElement
@XmlType(propOrder = { "count", "startPosition", "modificationFilter", "postModification" })
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
    protected byte[] modifyImplementationHook(byte[] input) {
        if (input == null) {
            input = new byte[0];
        }
        int start = startPosition;
        if (start < 0) {
            start += input.length;
            if (start < 0) {
                throw new IllegalArgumentException("Trying to delete from too negative Startposition. start = "
                        + (start - input.length));
            }
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
