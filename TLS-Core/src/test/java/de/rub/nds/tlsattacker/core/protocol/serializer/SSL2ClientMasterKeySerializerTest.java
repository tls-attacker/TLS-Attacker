/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SSL2CipherSuite;
import de.rub.nds.tlsattacker.core.constants.SSL2MessageType;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientMasterKeyMessage;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class SSL2ClientMasterKeySerializerTest
        extends AbstractProtocolMessageSerializerTest<
                SSL2ClientMasterKeyMessage, SSL2ClientMasterKeySerializer> {

    public SSL2ClientMasterKeySerializerTest() {
        super(
                SSL2ClientMasterKeyMessage::new,
                SSL2ClientMasterKeySerializer::new,
                List.of(
                        (msg, obj) -> msg.setType((byte) obj),
                        (msg, obj) -> msg.setMessageLength((Integer) obj),
                        (msg, obj) -> msg.setCipherKind((byte[]) obj),
                        (msg, obj) -> msg.setClearKeyLength((Integer) obj),
                        (msg, obj) -> msg.setEncryptedKeyLength((Integer) obj),
                        (msg, obj) -> msg.setKeyArgLength((Integer) obj),
                        (msg, obj) -> msg.setClearKeyData((byte[]) obj),
                        (msg, obj) -> msg.setEncryptedKeyData((byte[]) obj),
                        (msg, obj) -> msg.setKeyArgData((byte[]) obj),
                        (msg, obj) -> msg.setPaddingLength((Integer) obj)));
    }

    // TODO: Implement parser and move implementation of test vectors to parser test class
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ProtocolVersion.SSL2,
                        ArrayConverter.hexStringToByteArray(
                                "808a02010080000000800000b28367d5b44f6f585096540ab798705ecb6ce66336d5068952db71542701870754fdc25da8414d0977ec0401b5ff4cc853779d6069be867bf65a2250d14a189d74c608f4f76a9aa8a4f1a909370b86f5fd0740d368083e78e1034e38573b32799cf59ea52a771633ffdbd0e8123ada764f677cd09b05106ea9af8168a71249d4"),
                        Arrays.asList(
                                SSL2MessageType.SSL_CLIENT_MASTER_KEY.getType(),
                                138,
                                BigInteger.valueOf(
                                                SSL2CipherSuite.SSL_CK_RC4_128_WITH_MD5.getValue())
                                        .toByteArray(),
                                0,
                                128,
                                0,
                                new byte[0],
                                ArrayConverter.hexStringToByteArray(
                                        "b28367d5b44f6f585096540ab798705ecb6ce66336d5068952db71542701870754fdc25da8414d0977ec0401b5ff4cc853779d6069be867bf65a2250d14a189d74c608f4f76a9aa8a4f1a909370b86f5fd0740d368083e78e1034e38573b32799cf59ea52a771633ffdbd0e8123ada764f677cd09b05106ea9af8168a71249d4"),
                                new byte[0],
                                0)));
    }
}
