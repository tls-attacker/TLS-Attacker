/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.context;

import de.rub.nds.tlsattacker.core.protocol.Parser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class MessageParserBoundaryVerificationContext implements ParserContext {

    private static final Logger LOGGER = LogManager.getLogger();

    private final boolean throwing;

    private final int boundary;

    private final String boundaryQualifier;

    private final int pointerOffset;

    public MessageParserBoundaryVerificationContext(int boundary, String boundaryQualifier, int pointerOffset,
        boolean throwing) {
        super();
        this.throwing = throwing;
        this.boundary = boundary;
        this.boundaryQualifier = boundaryQualifier;
        this.pointerOffset = pointerOffset;
    }

    @Override
    public ParserContextResult beforeParse(final Parser p, final int requestedLength, final ParserContext previous) {
        int requestedBoundary = (p.getPointer() - pointerOffset) + requestedLength;
        LOGGER.trace("Verify requested boundary {} against boundary {} {}", requestedBoundary, boundaryQualifier,
            boundary);
        if (requestedBoundary <= this.boundary) {
            return ParserContextResult.NULL_RESULT;
        } else {
            return new ParserContextResult() {
                @Override
                public void evaluate() {
                    String message = String.format(
                        "Attempt to parse over boundary %s while in context %s, "
                            + "boundary only has %d bytes left, but parse request was for %d bytes in %s",
                        boundaryQualifier, previous != null ? previous.toString() : "Message",
                        MessageParserBoundaryVerificationContext.this.boundary - (p.getPointer() - pointerOffset),
                        requestedLength, MessageParserBoundaryVerificationContext.this);
                    if (throwing) {
                        throw new ParserContextParserException(message, MessageParserBoundaryVerificationContext.this,
                            previous);
                    } else {
                        LOGGER.debug(message);
                    }
                }
            };
        }
    }

    @Override
    public String toString() {
        return "MessageParserBoundaryContext [boundary=" + boundary + ", boundaryQualifier=" + boundaryQualifier
            + ", pointerOffset=" + pointerOffset + "]";
    }
}
