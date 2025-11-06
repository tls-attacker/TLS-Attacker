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
import de.rub.nds.protocol.exception.EndOfStreamException;
import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Abstract Parser class which can be used to read a byte array.
 *
 * @param <T> Type of the Object that should be parsed
 */
public abstract class Parser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final InputStream stream;

    /**
     * quicBuffer is used as a helper to construct the original QuicHeader for PacketDecryption.
     * there might be a nicer solution.
     */
    protected SilentByteArrayOutputStream quicBuffer = new SilentByteArrayOutputStream();

    /** Not so nice... */
    private final SilentByteArrayOutputStream outputStream;

    /**
     * Constructor for the Parser
     *
     * @param stream The Inputstream to read data drom
     */
    protected Parser(InputStream stream) {
        this.stream = stream;
        outputStream = new SilentByteArrayOutputStream();
    }

    public byte[] getAlreadyParsed() {
        return outputStream.toByteArray();
    }

    /**
     * Parses a number of bytes from the Array and returns them as a byte[].
     *
     * @param length Number of bytes to be parsed
     * @return A subByteArray of according size from the Array
     */
    protected byte[] parseByteArrayField(int length) {
        if (length == 0) {
            return new byte[0];
        }
        if (length < 0) {
            throw new ParserException("Trying to parse a negative amount of bytes");
        }
        byte[] data = new byte[length];
        try {
            int read = stream.read(data);
            if (read == -1) {
                throw new EndOfStreamException("Reached end of Stream");
            }
            if (read != length) {
                throw new EndOfStreamException("Reached end of stream after " + read + " bytes");
            } else {
                outputStream.write(data);
            }
        } catch (IOException E) {
            throw new ParserException("Could not parse byteArrayField of length=" + length, E);
        }
        return data;
    }

    /**
     * Parses a number of bytes from the Array and returns them as a int. Throws a ParserException
     * if the number of bytes cannot be parsed. Moves the pointer accordingly.
     *
     * @param length Number of bytes to be parsed
     * @return An integer representation of the subByteArray
     */
    protected int parseIntField(int length) {
        if (length == 0) {
            throw new ParserException("Cannot parse int of size 0");
        }
        return DataConverter.bytesToInt(parseByteArrayField(length));
    }

    /**
     * Parses a number of bytes from the Array and returns them as a positive BigInteger. Throws a
     * ParserException if the number of bytes cannot be parsed. Moves the pointer accordingly.
     *
     * @param length Number of bytes to be parsed
     * @return A BigInteger representation of the subByteArray
     */
    protected BigInteger parseBigIntField(int length) {
        if (length == 0) {
            throw new ParserException("Cannot parse BigInt of size 0");
        }
        return new BigInteger(1, parseByteArrayField(length));
    }

    /**
     * Parses a number of bytes from the Array and returns them as a byte. Throws a ParserException
     * if the number of bytes cannot be parsed. Moves the pointer accordingly.
     *
     * @param length Number of bytes to be parsed
     * @return An integer representation of the subByteArray
     */
    protected byte parseByteField(int length) {
        if (length == 0) {
            throw new ParserException("Cannot parse byte of size 0");
        }
        if (length > 1) {
            LOGGER.warn("Parsing byte[] field into a byte of size >1");
        }
        return (byte) DataConverter.bytesToInt(parseByteArrayField(length));
    }

    /**
     * Parses as US_ASCII
     *
     * @param endSequence
     * @return
     */
    protected String parseStringTill(byte endSequence) {
        SilentByteArrayOutputStream tempStream = new SilentByteArrayOutputStream();
        while (true) {
            byte b = parseByteField(1);
            tempStream.write(b);
            if (b == endSequence) {
                return tempStream.toString(StandardCharsets.US_ASCII);
            }
        }
    }

    /**
     * Checks if there are at least count bytes left to read
     *
     * @param count Number of bytes to check for
     * @return True if there are at least count bytes left to read
     */
    protected boolean enoughBytesLeft(int count) {
        return getBytesLeft() >= count;
    }

    protected byte[] parseArrayOrTillEnd(int n) {
        if (n >= 0 && n < getBytesLeft()) {
            return parseByteArrayField(n);
        } else {
            return parseByteArrayField(getBytesLeft());
        }
    }

    protected byte[] parseTillEnd() {
        return parseByteArrayField(getBytesLeft());
    }

    public int getBytesLeft() {
        try {
            return stream.available();
        } catch (IOException ex) {
            throw new ParserException("Cannot tell how many bytes are left in inputstream", ex);
        }
    }

    /**
     * Returns the parsed object.
     *
     * @param t object that should be filled with content
     */
    public abstract void parse(T t);

    /**
     * TODO: This can break get already parsed - not so nice
     *
     * @return
     */
    protected InputStream getStream() {
        return stream;
    }

    /**
     * Parses the VariableLengthInteger from the InputStream
     *
     * @return [0] the Integer Value [1] the size in bytes of the encoded Integer Value (Used for
     *     Packet Decryption)
     */
    protected long parseVariableLengthInteger() {
        byte b = parseByteField(1);
        quicBuffer.write(b);
        long v = b;
        byte prefix = (byte) ((v & 0xff) >> 6);
        byte length = (byte) ((1 & 0xff) << prefix);
        v = (byte) v & 0x3f;
        for (int i = 0; i < length - 1; i++) {
            b = parseByteField(1);
            quicBuffer.write(b);
            v = (v << 8) + (b & 0xff);
        }
        return v;
    }
}
