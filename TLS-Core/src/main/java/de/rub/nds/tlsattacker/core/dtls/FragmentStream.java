/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.dtls;

import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class FragmentStream {

    private static final Logger LOGGER = LogManager.getLogger();

    private HashMap<Integer, Byte> fragmentByteMap;

    private int intendedSize;

    public FragmentStream(int intendedSize) {
        fragmentByteMap = new HashMap<>();
        this.intendedSize = intendedSize;
    }

    public boolean canInsertByteArray(byte[] bytesToAdd, int offset) {
        for (int i = 0; i < bytesToAdd.length; i++) {
            if (fragmentByteMap.containsKey(offset + i)) {
                if (fragmentByteMap.get(offset + i) != bytesToAdd[i]) {
                    return false;
                }
            }
        }
        return true;
    }

    public void insertByteArray(byte[] bytesToAdd, int offset) {
        for (int i = 0; i < bytesToAdd.length; i++) {
            if (fragmentByteMap.containsKey(offset + i)) {
                fragmentByteMap.remove(offset + i);
            }
            fragmentByteMap.put(offset + i, bytesToAdd[i]);
        }
    }

    /**
     * Checks if the fragment stream is complete up to the specified index
     *
     * @param tillIndex Bytes till the maximum index
     * @return true if all keys are in the map, otherwise false
     */
    public boolean isComplete(int tillIndex) {
        if (tillIndex < 0) {
            throw new IllegalArgumentException(
                    "Cannot check stream for completeness with negative index: " + tillIndex);
        }
        for (int i = 0; i < tillIndex; i++) {
            if (!fragmentByteMap.containsKey(i)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Returns the fragment streams contents and fills any holes in it with the specified filling
     * byte
     *
     * @param fillingByte the byte with which we fill holes in the fragment
     * @return the stream
     */
    public byte[] getCompleteFilledStream(byte fillingByte) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        int fillingCounter = 0;
        for (int i = 0; i < intendedSize; i++) {
            Byte b = fragmentByteMap.get(i);
            if (b == null) {
                b = fillingByte;
                fillingCounter++;
            }
            stream.write(b);
        }
        if (fillingCounter > 0) {
            LOGGER.warn(
                    "Had to fill "
                            + fillingCounter
                            + " missing bytes in HandshakeMessageFragments. This will _likely_ result in invalid messages");
        }
        for (Integer i : fragmentByteMap.keySet()) {
            if (i > intendedSize) {
                LOGGER.warn(
                        "Found fragment greater than intended message size(intended size: "
                                + intendedSize
                                + " but found byte for: "
                                + i
                                + "). Ignoring");
            }
        }
        return stream.toByteArray();
    }

    public byte[] getCompleteTruncatedStream() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        int skipCounter = 0;
        for (int i = 0; i < intendedSize; i++) {
            Byte b = fragmentByteMap.get(i);
            if (b == null) {
                skipCounter++;
                continue;
            }
            stream.write(b);
        }
        if (skipCounter > 0) {
            LOGGER.warn("Did not receive all bytes. Truncated  " + skipCounter + " missing bytes.");
        }
        for (Integer i : fragmentByteMap.keySet()) {
            if (i > intendedSize) {
                LOGGER.warn(
                        "Found fragment greater than intended message size(intended size: "
                                + intendedSize
                                + " but found byte for: "
                                + i
                                + "). Ignoring");
            }
        }
        return stream.toByteArray();
    }
}
