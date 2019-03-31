/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.context;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;

public class MessageParserBoundaryVerificationContext implements ParserContext {

<<<<<<< HEAD
    public static boolean THROWING = false;

=======
>>>>>>> Adding ParserContext to verify double length parsing
    private static final Logger LOGGER = LogManager.getLogger();

    private final int messageBoundary;

    private final String boundaryQualifier;

    private final int pointerOffset;

    public MessageParserBoundaryVerificationContext(int boundary, String boundaryQualifier, int pointerOffset) {
        super();
        this.messageBoundary = boundary;
        this.boundaryQualifier = boundaryQualifier;
        this.pointerOffset = pointerOffset;
    }

    @Override
    public ParserContextResult beforeParse(final Parser p, final int requestedLength) {
        int requestedBoundary = (p.getPointer() - pointerOffset) + requestedLength;
        LOGGER.trace("verify requested boundary {} against boundary {} {}", requestedBoundary, boundaryQualifier,
                messageBoundary);
        if (requestedBoundary <= this.messageBoundary) {
            return ParserContextResult.NULL_RESULT;
        } else {
            return new ParserContextResult() {
                @Override
                public void evaluate() {
<<<<<<< HEAD
                    String message = String.format("Attempt to parse over boundary %s of current context, "
=======
                    throw new ParserException(String.format("Attempt to parse over boundary %s of current context, "
>>>>>>> Adding ParserContext to verify double length parsing
                            + "boundary only has %d bytes left, but parse request was for %d bytes in %s",
                            boundaryQualifier,
                            MessageParserBoundaryVerificationContext.this.messageBoundary
                                    - (p.getPointer() - pointerOffset), requestedLength,
<<<<<<< HEAD
                            MessageParserBoundaryVerificationContext.this);
                    if (THROWING) {
                        throw new ParserException(message);
                    } else {
                        LOGGER.info(message);
                    }
=======
                            MessageParserBoundaryVerificationContext.this));
>>>>>>> Adding ParserContext to verify double length parsing
                }
            };
        }
    }

    @Override
    public String toString() {
        return "MessageParserBoundaryContext [boundary=" + messageBoundary + ", boundaryQualifier=" + boundaryQualifier
                + ", pointerOffset=" + pointerOffset + "]";
    }
}
