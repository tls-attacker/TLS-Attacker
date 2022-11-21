/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.protocol.parser.context.ParserContext;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.ListIterator;
import java.util.Stack;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Abstract Parser class which can be used to read a byte array.
 *
 * @param <T>
 *            Type of the Object that should be parsed
 */
public abstract class Parser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Current position in the byte array
     */
    private int pointer;
    /**
     * Array that should be parsed
     */
    private final byte[] array;
    /**
     * Start position of the parser
     */
    private final int startPoint;
    /**
     * Stack of parser contexts to be evaluated
     */
    private final Stack<ParserContext> context;

    /**
     * Constructor for the Parser
     *
     * @param startposition
     *                      Position in the array from which the Parser should start working
     * @param array
     *                      Array that should be parsed
     */
    public Parser(int startposition, byte[] array) {
        this.startPoint = startposition;
        this.pointer = startposition;
        this.array = array;
        if (startposition > array.length) {
            throw new ParserException(
                "Cannot create parser beyond pointer. Pointer:" + pointer + " ArrayLength:" + array.length);
        }
        this.context = new Stack<>();
    }

    /**
     * Parses a number of bytes from the Array and returns them as a byte[]. Throws a ParserException if the number of
     * bytes cannot be parsed. Moves the pointer accordingly.
     *
     * @param  length
     *                Number of bytes to be parsed
     * @return        A subByteArray of according size from the Array
     */
    protected byte[] parseByteArrayField(int length) {
        LOGGER.trace("Request to parse {} bytes with pointer at {}", length, getPointer());
        if (length == 0) {
            return new byte[0];
        }
        if (length < 0) {
            throw new ParserException("Cannot parse field of size " + length);
        }
        beforeParseRequest(length);
        int nextPointer = pointer + length;
        if (!enoughBytesLeft(length)) {
            throw new ParserException("Parsing over the end of the array. Current Pointer:" + pointer
                + " ToParse Length:" + length + " ArrayLength:" + array.length);
        }
        byte[] result = Arrays.copyOfRange(array, pointer, nextPointer);
        pointer = nextPointer;
        LOGGER.trace("Next pointer at {}", getPointer());
        return result;
    }

    /**
     * Parses a number of bytes from the Array and returns them as a int. Throws a ParserException if the number of
     * bytes cannot be parsed. Moves the pointer accordingly.
     *
     * @param  length
     *                Number of bytes to be parsed
     * @return        An integer representation of the subByteArray
     */
    protected int parseIntField(int length) {
        if (length == 0) {
            throw new ParserException("Cannot parse int of size 0");
        }
        return ArrayConverter.bytesToInt(parseByteArrayField(length));
    }

    /**
     * Parses a number of bytes from the Array and returns them as a positive BigInteger. Throws a ParserException if
     * the number of bytes cannot be parsed. Moves the pointer accordingly.
     *
     * @param  length
     *                Number of bytes to be parsed
     * @return        A BigInteger representation of the subByteArray
     */
    protected BigInteger parseBigIntField(int length) {
        if (length == 0) {
            throw new ParserException("Cannot parse BigInt of size 0");
        }
        return new BigInteger(1, parseByteArrayField(length));
    }

    /**
     * Parses a number of bytes from the Array and returns them as a byte. Throws a ParserException if the number of
     * bytes cannot be parsed. Moves the pointer accordingly.
     *
     * @param  length
     *                Number of bytes to be parsed
     * @return        An integer representation of the subByteArray
     */
    protected byte parseByteField(int length) {
        if (length == 0) {
            throw new ParserException("Cannot parse byte of size 0");
        }
        if (length > 1) {
            LOGGER.warn("Parsing byte[] field into a byte of size >1");
        }
        return (byte) ArrayConverter.bytesToInt(parseByteArrayField(length));
    }

    protected String parseStringTill(byte endSequence) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        while (true) {
            byte b = parseByteField(1);
            stream.write(b);
            if (b == endSequence) {
                return stream.toString();
            }
        }
    }

    /**
     * Returns the byte at the current pointer position
     *
     * @return byte at the current pointer position
     */
    protected byte peek() {
        if (pointer < array.length) {
            return array[pointer];
        } else {
            throw new ParserException("Cannot peek, would peek over the end ot the array");
        }
    }

    /**
     * Returns the current position of the pointer in the array
     *
     * @return Current position of the pointer in the array
     */
    public int getPointer() {
        return pointer;
    }

    /**
     * Set the current position of the pointer in the array
     *
     * @param pointer
     *                The new position of the pointer in the array
     */
    public void setPointer(int pointer) {
        this.pointer = pointer;
    }

    /**
     * Returns the position at which the Parser started parsing
     *
     * @return The Start position of the Parser
     */
    public int getStartPoint() {
        return startPoint;
    }

    /**
     * Returns a byte[] of the already parsed bytes.
     *
     * @return Array of the already parsed bytes.
     */
    protected byte[] getAlreadyParsed() {
        return Arrays.copyOfRange(array, startPoint, pointer);
    }

    /**
     * Checks if there are at least count bytes left to read
     *
     * @param  count
     *               Number of bytes to check for
     * @return       True if there are at least count bytes left to read
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

    public int getBytesLeft() {
        return array.length - pointer;
    }

    protected void pushContext(ParserContext parserContext) {
        LOGGER.trace("Pushing new context {}", parserContext);
        context.push(parserContext);
    }

    protected ParserContext popContext() {
        if (!context.isEmpty()) {
            return context.pop();
        } else {
            return null;
        }
    }

    private void beforeParseRequest(int length) {
        if (!context.isEmpty()) {
            ListIterator<ParserContext> listIterator = context.listIterator(context.size());
            ParserContext prev = null;
            while (listIterator.hasPrevious()) {
                ParserContext ctx = listIterator.previous();
                ctx.beforeParse(this, length, prev).evaluate();
                prev = ctx;
            }
        }
    }

    /**
     * Returns the parsed object.
     *
     * @return The parsed object
     */
    public abstract T parse();

}
