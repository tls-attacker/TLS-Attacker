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
import de.rub.nds.tlsattacker.util.ByteArrayAdapter;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * Shuffles the byte array, using a pre-defined array of array pointers
 * (#shuffle). Array pointers are currently defined as bytes, since we are
 * modifying rather smaller arrays.
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
@XmlRootElement
@XmlType(propOrder = { "shuffle", "modificationFilter", "postModification" })
public class ByteArrayShuffleModification extends VariableModification<byte[]> {

    private byte[] shuffle;

    public ByteArrayShuffleModification() {

    }

    public ByteArrayShuffleModification(byte[] shuffle) {
        this.shuffle = shuffle;
    }

    @Override
    protected byte[] modifyImplementationHook(final byte[] input) {
        byte[] result = input.clone();
        int size = input.length;
        for (int i = 0; i < shuffle.length - 1; i += 2) {
            int p1 = (shuffle[i] & 0xff) % size;
            int p2 = (shuffle[i + 1] & 0xff) % size;
            byte tmp = result[p1];
            result[p1] = result[p2];
            result[p2] = tmp;
        }
        return result;
    }

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    public byte[] getShuffle() {
        return shuffle;
    }

    public void setShuffle(byte[] shuffle) {
        this.shuffle = shuffle;
    }
}
