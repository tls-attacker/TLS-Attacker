/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer;

import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;

/**
 * The Serializer is responsible to write an Object T into a byte[] form. This
 * is comparable to byte[] serialization.
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T> Type of the Object to write
 */
public abstract class Serializer<T> {

    /**
     * The ByteArrayOutputStream with which the byte[] is constructed.
     */
    private final ByteArrayOutputStream outputStream;

    /**
     * Constructor for the Serializer
     */
    public Serializer() {
        outputStream = new ByteArrayOutputStream();
    }

    /**
     * This method is responsible to write the appropriate bytes to the output
     * Stream This should be done by calling the different append methods.
     */
    protected abstract void serializeBytes();

    /**
     * Adds a byte[] representation of an int to the final byte[]. If the
     * Integer is greater than the specified length only the lower length bytes
     * are serialized.
     *
     * @param i The Integer that should be appended
     * @param length The number of bytes which should be reserved for this Integer
     */
    protected final void appendInt(int i, int length) {
        byte[] bytes = ArrayConverter.intToBytes(i, length);
        int reconvertedInt = ArrayConverter.bytesToInt(bytes);
        if (reconvertedInt != i) {
            LOGGER.warn("Int \"" + i + "\" is too long to write in field of size " + length + ". Only using last " + length + " bytes.");
        }
        appendBytes(ArrayConverter.intToBytes(i, length));
    }

    /**
     * Adds a byte to the final byte[].
     * @param b Byte which should be added
     */
    protected final void appendByte(byte b) {
        outputStream.write(b);
    }

    /**
     * Adds a byte[] to the final byte[].
     * @param bytes bytes that should be added
     */
    protected final void appendBytes(byte[] bytes) {
        try {
            outputStream.write(bytes);
        } catch (IOException ex) {
            LOGGER.warn("Encountered exception while writing to ByteArrayOutputStream.", ex);
        }
    }

    /**
     * Creates the final byte[]
     * @return The final byte[]
     */
    public final byte[] serialize() {
        serializeBytes();
        return outputStream.toByteArray();
    }

    private static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger(Serializer.class);
}
