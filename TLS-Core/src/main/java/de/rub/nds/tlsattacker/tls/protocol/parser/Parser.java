/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.exceptions.ParserException;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * Abstract Parser class which can be used to read a byte array.
 * @author Robert Merget - robert.merget@rub.de
 * @param <T> Type of the Object that should be parsed
 */
public abstract class Parser<T> {
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
     * Constructor for the Parser
     * @param startposition Position in the array from which the Parser should start working
     * @param array Array that should be parsed
     */
    public Parser(int startposition, byte[] array) {
        this.startPoint = startposition;
        this.pointer = startposition;
        this.array = array;
        if(startposition >= array.length)
        {
            throw new ParserException("Cannot creater parser beyond pointer");
        }
    }
    
    /**
     * Parses a number of bytes from the Array and returns them as a byte[].
     * Throws a ParserException if the number of bytes cannot be parsed. Moves 
     * the pointer accordingly.
     * @param length Number of bytes to be parsed
     * @return A subbyteArray of according size from the Array
     */
    protected byte[] parseByteArrayField(int length)
    {
        if(length < 1)
        {
            throw new ParserException("Cannot parse field of size "+length);
        }
        int nextPointer = pointer + length;
        if(nextPointer > array.length)
        {
            throw new ParserException("Parsing over the end of the array");
        }
        byte[] result = Arrays.copyOfRange(array, pointer, nextPointer);
        pointer = nextPointer;
        return result;
    }
    
    /**
     * Parses a number of bytes from the Array and returns them as a int.
     * Throws a ParserException if the number of bytes cannot be parsed. Moves 
     * the pointer accordingly.
     * @param length Number of bytes to be parsed
     * @return An integer representation of the subbyteArray
     */
    protected int parseIntField(int length)
    {
        return ArrayConverter.bytesToInt(parseByteArrayField(length));
    }
    
    /**
     * Parses a number of bytes from the Array and returns them as a byte.
     * Throws a ParserException if the number of bytes cannot be parsed. Moves 
     * the pointer accordingly.
     * @param length Number of bytes to be parsed
     * @return An integer representation of the subbyteArray
     */
    protected byte parseByteField(int length)
    {
        if(length > 0)
        {
            LOGGER.warn("Parsing byte[] field into a byte of size >1");
        }
        return (byte)ArrayConverter.bytesToInt(parseByteArrayField(length));
    }
    
    /**
     * Returns the current position of the pointer in the array
     * @return Current position of the pointer in the array
     */
    public int getPointer() {
        return pointer;
    }
    
    /**
     * Returns the position at which the Parser started parsing
     * @return 
     */
    public int getStartPoint() {
        return startPoint;
    }
    
    /**
     * Returns a byte[] of the already parsed bytes.
     * @return Array of the already parsed bytes.
     */
    protected byte[] getAlreadyParsed()
    {
        return Arrays.copyOfRange(array,startPoint,pointer);
    }
    
    /**
     * Returns the parsed object.
     * @return The parsed object
     */
    public abstract T parse();
    
    private static final Logger LOGGER = LogManager.getLogger(Parser.class);
}
