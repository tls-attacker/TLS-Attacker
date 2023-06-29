/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class SessionTicketTLSExtensionSerializerTest
        extends AbstractExtensionMessageSerializerTest<
                SessionTicketTLSExtensionMessage, SessionTicketTLSExtensionSerializer> {

    public SessionTicketTLSExtensionSerializerTest() {
        super(
                SessionTicketTLSExtensionMessage::new,
                SessionTicketTLSExtensionSerializer::new,
                List.of((msg, obj) -> msg.getSessionTicket().setIdentity((byte[]) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "002300A07710f36a53b83f7b298b0cbf7863cfb14c26f9189edce8cf0ad181ddf706e2c358034c1d59c4c80e85ea2cda9de6f6373db1f7a95d4ce2941646a282de1b6ad9122605cf6579d04c1bd145192a0fecf9f617620d5c4c0fe00fdc9b7ae2a2350e1ca22a88b6233cef19c846c92349417e5a841d2d75b42767d1b589cd7509740a94c83b23a268ecc6ff526fc5b199a3784d7b1b800913aceea695c499fb238896"),
                        List.of(),
                        ExtensionType.SESSION_TICKET,
                        160,
                        Arrays.asList(
                                ArrayConverter.hexStringToByteArray(
                                        "7710f36a53b83f7b298b0cbf7863cfb14c26f9189edce8cf0ad181ddf706e2c358034c1d59c4c80e85ea2cda9de6f6373db1f7a95d4ce2941646a282de1b6ad9122605cf6579d04c1bd145192a0fecf9f617620d5c4c0fe00fdc9b7ae2a2350e1ca22a88b6233cef19c846c92349417e5a841d2d75b42767d1b589cd7509740a94c83b23a268ecc6ff526fc5b199a3784d7b1b800913aceea695c499fb238896"))));
    }
}
