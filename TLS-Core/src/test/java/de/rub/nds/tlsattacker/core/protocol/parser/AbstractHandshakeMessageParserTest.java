/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2Message;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.function.BiFunction;
import java.util.function.Function;
import org.junit.jupiter.api.Named;

abstract class AbstractHandshakeMessageParserTest<
                MT extends HandshakeMessage, PT extends HandshakeMessageParser<MT>>
        extends AbstractProtocolMessageParserTest<MT, PT> {

    AbstractHandshakeMessageParserTest(
            Class<MT> messageClass, BiFunction<InputStream, TlsContext, PT> parserConstructor) {
        this(messageClass, parserConstructor, List.of());
    }

    AbstractHandshakeMessageParserTest(
            Class<MT> messageClass,
            BiFunction<InputStream, TlsContext, PT> parserConstructor,
            List<Named<Function<MT, Object>>> messageGetters) {
        super(messageClass, parserConstructor, messageGetters);
    }

    @Override
    protected ByteArrayInputStream getMessageInputStream(byte[] providedMessageBytes) {
        // Remove headers as these will be handled by the RecordLayer
        if (!SSL2Message.class.isAssignableFrom(messageClass)) {
            return new ByteArrayInputStream(
                    Arrays.copyOfRange(
                            providedMessageBytes,
                            HandshakeByteLength.MESSAGE_TYPE
                                    + HandshakeByteLength.MESSAGE_LENGTH_FIELD,
                            providedMessageBytes.length));
        } else {
            return new ByteArrayInputStream(providedMessageBytes);
        }
    }

    @Override
    protected void parseTlsMessage(
            ProtocolVersion providedProtocolVersion, byte[] providedMessageBytes) {
        super.parseTlsMessage(providedProtocolVersion, providedMessageBytes);
    }

    @Override
    protected void assertMessageSpecific(List<Object> expectedMessageSpecificValues) {
        // Remove Type and length as they are not covered by low-level parser
        List<Object> modifiedExpected = new LinkedList<>(expectedMessageSpecificValues);
        modifiedExpected.remove(0);
        modifiedExpected.remove(0);
        super.assertMessageSpecific(modifiedExpected);
    }
}
