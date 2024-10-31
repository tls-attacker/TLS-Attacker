/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.protocol.exception.EndOfStreamException;
import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2Message;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import java.io.ByteArrayInputStream;
import java.lang.reflect.InvocationTargetException;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class ParserSerializerIT extends GenericParserSerializerTest {

    private static final Logger LOGGER = LogManager.getLogger();
    private final Config config = new Config();

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testParser()
            throws NoSuchMethodException,
                    InstantiationException,
                    IllegalAccessException,
                    IllegalAccessException,
                    IllegalArgumentException,
                    IllegalArgumentException,
                    InvocationTargetException {
        Random r = new Random(42);
        for (int i = 0; i < 10000; i++) {
            ProtocolMessage message = null;
            TlsContext tlsContext =
                    new Context(new State(config), new InboundConnection()).getTlsContext();
            byte[] bytesToParse = null;
            try {
                int length = r.nextInt(1000);
                bytesToParse = new byte[length];
                r.nextBytes(bytesToParse);
                message = getRandomMessage(r);
                Parser parser =
                        message.getParser(
                                tlsContext.getContext(), new ByteArrayInputStream(bytesToParse));
                parser.parse(message);
            } catch (ParserException | EndOfStreamException E) {
                continue;
            }

            if (message instanceof HandshakeMessage && !(message instanceof SSL2Message)) {
                // TODO: review if this test can be applied to HandshakeMessage's
                continue;
            }
            message.getPreparator(tlsContext.getContext());
            Serializer<? extends ProtocolMessage> serializer =
                    message.getSerializer(tlsContext.getContext());
            byte[] result = serializer.serialize();
            LOGGER.debug(message.toString());
            LOGGER.debug("Bytes to parse:\t{}", bytesToParse);
            LOGGER.debug("Result:\t{}", result);
            Parser parser2 =
                    message.getParser(tlsContext.getContext(), new ByteArrayInputStream(result));
            ProtocolMessage serialized = message.getClass().getConstructor().newInstance();
            parser2.parse(serialized);
            LOGGER.debug(serialized.toString());
            assertArrayEquals(serialized.getCompleteResultingMessage().getValue(), result);
        }
    }
}
