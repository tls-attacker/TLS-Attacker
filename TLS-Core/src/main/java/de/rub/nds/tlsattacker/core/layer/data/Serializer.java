/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.data;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The Serializer is responsible to write an Object T into a byte[] form. This is comparable to
 * byte[] serialization.
 *
 * @param <T> Type of the Object to write
 */
public abstract class Serializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    /** The SilentByteArrayOutputStream with which the byte[] is constructed. */
    private SilentByteArrayOutputStream outputStream;

    /** Constructor for the Serializer */
    public Serializer() {
        outputStream = new SilentByteArrayOutputStream();
    }

    /**
     * This method is responsible to write the appropriate bytes to the output Stream This should be
     * done by calling the different append methods.
     *
     * @return The already serialized Bytes
     */
    protected abstract byte[] serializeBytes();

    /**
     * Adds a byte[] representation of an int to the final byte[]. If the Integer is greater than
     * the specified length only the lower length bytes are serialized.
     *
     * @param i The Integer that should be appended
     * @param length The number of bytes which should be reserved for this Integer
     */
    public final void appendInt(int i, int length) {
        byte[] bytes = DataConverter.intToBytes(i, length);
        int reconvertedInt = DataConverter.bytesToInt(bytes);
        if (reconvertedInt != i) {
            LOGGER.warn(
                    "Int \"{}\" is too long to write in field of size {}. Only using last {} bytes.",
                    i,
                    length,
                    length);
        }
        appendBytes(bytes);
    }

    /**
     * Adds a byte[] representation of a BigInteger to the final byte[] minus the sign byte. If the
     * BigInteger is greater than the specified length only the lower length bytes are serialized.
     *
     * @param i The BigInteger that should be appended
     * @param length The number of bytes which should be reserved for this BigInteger
     */
    public final void appendBigInteger(BigInteger i, int length) {
        byte[] bytes;
        // special case for which bigIntegerToByteArray
        // wrongly returns an empty array
        if (i.equals(BigInteger.ZERO)) {
            bytes = DataConverter.intToBytes(0, length);
        } else {
            bytes = DataConverter.bigIntegerToByteArray(i, length, true);
        }
        appendBytes(bytes);
    }

    /**
     * Adds a byte to the final byte[].
     *
     * @param b Byte which should be added
     */
    public final void appendByte(byte b) {
        outputStream.write(b);
    }

    /**
     * Adds a byte[] to the final byte[].
     *
     * @param bytes bytes that should be added
     */
    public final void appendBytes(byte[] bytes) {
        outputStream.write(bytes);
    }

    public final byte[] getAlreadySerialized() {
        return outputStream.toByteArray();
    }

    /**
     * Creates the final byte[]
     *
     * @return The final byte[]
     */
    public final byte[] serialize() {
        outputStream = new SilentByteArrayOutputStream();
        serializeBytes();
        return getAlreadySerialized();
    }

    public SilentByteArrayOutputStream getOutputStream() {
        return outputStream;
    }
}
