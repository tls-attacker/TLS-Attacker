/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.pq.PQUtils;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class KeyShareExtensionSerializerTest
        extends AbstractExtensionMessageSerializerTest<
                KeyShareExtensionMessage, KeyShareExtensionSerializer> {

    public KeyShareExtensionSerializerTest() {
        super(
                KeyShareExtensionMessage::new,
                (msg) -> new KeyShareExtensionSerializer(msg, ConnectionEndType.CLIENT),
                List.of(
                        (msg, obj) -> msg.setKeyShareListLength((Integer) obj),
                        (msg, obj) -> msg.setKeyShareListBytes((byte[]) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        byte[] hybridEntry =
                hybridKeyShareEntry(NamedGroup.X25519_MLKEM768, ConnectionEndType.CLIENT);

        return Stream.of(
                Arguments.of(
                        DataConverter.hexStringToByteArray(
                                "003300260024001d00206786b901eb52a2578a57195d897b8329cb630a19617352af9163c69e0f9a4204"),
                        List.of(),
                        ExtensionType.KEY_SHARE,
                        38,
                        Arrays.asList(
                                36,
                                DataConverter.hexStringToByteArray(
                                        "001d00206786b901eb52a2578a57195d897b8329cb630a19617352af9163c69e0f9a4204"))),
                Arguments.of(
                        clientExtensionBytes(hybridEntry),
                        List.of(),
                        ExtensionType.KEY_SHARE,
                        ExtensionByteLength.KEY_SHARE_LIST_LENGTH + hybridEntry.length,
                        Arrays.asList(hybridEntry.length, hybridEntry)));
    }

    private static byte[] hybridKeyShareEntry(
            NamedGroup namedGroup, ConnectionEndType connectionEndType) {
        int publicKeyLength =
                PQUtils.getEcPublicKeyLength(namedGroup)
                        + PQUtils.getPQKeyShareLength(namedGroup, connectionEndType);
        return DataConverter.concatenate(
                namedGroup.getValue(),
                DataConverter.intToBytes(publicKeyLength, ExtensionByteLength.KEY_SHARE_LENGTH),
                publicKeyBytes(publicKeyLength));
    }

    private static byte[] clientExtensionBytes(byte[] keyShareEntry) {
        byte[] extensionPayload =
                DataConverter.concatenate(
                        DataConverter.intToBytes(
                                keyShareEntry.length, ExtensionByteLength.KEY_SHARE_LIST_LENGTH),
                        keyShareEntry);
        return DataConverter.concatenate(
                ExtensionType.KEY_SHARE.getValue(),
                DataConverter.intToBytes(
                        extensionPayload.length, ExtensionByteLength.EXTENSIONS_LENGTH),
                extensionPayload);
    }

    private static byte[] publicKeyBytes(int length) {
        byte[] publicKey = new byte[length];
        for (int i = 0; i < length; i++) {
            publicKey[i] = (byte) i;
        }
        return publicKey;
    }
}
