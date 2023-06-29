/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import static de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage.EsniMessageType;

import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EncryptedServerNameIndicationExtensionParserTest;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class EncryptedServerNameIndicationExtensionSerializerTest
        extends AbstractExtensionMessageSerializerTest<
                EncryptedServerNameIndicationExtensionMessage,
                EncryptedServerNameIndicationExtensionSerializer> {

    public EncryptedServerNameIndicationExtensionSerializerTest() {
        super(
                EncryptedServerNameIndicationExtensionMessage::new,
                EncryptedServerNameIndicationExtensionSerializer::new,
                List.of(
                        (msg, obj) -> msg.setEsniMessageTypeConfig((EsniMessageType) obj),
                        (msg, obj) -> msg.setCipherSuite((byte[]) obj),
                        (msg, obj) -> msg.getKeyShareEntry().setGroup((byte[]) obj),
                        (msg, obj) -> msg.getKeyShareEntry().setPublicKeyLength((Integer) obj),
                        (msg, obj) -> msg.getKeyShareEntry().setPublicKey((byte[]) obj),
                        (msg, obj) -> msg.setRecordDigestLength((Integer) obj),
                        (msg, obj) -> msg.setRecordDigest((byte[]) obj),
                        (msg, obj) -> msg.setEncryptedSniLength((Integer) obj),
                        (msg, obj) -> msg.setEncryptedSni((byte[]) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return EncryptedServerNameIndicationExtensionParserTest.provideTestVectors();
    }
}
