/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

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
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class KeyShareExtensionParserTest
        extends AbstractExtensionParserTest<KeyShareExtensionMessage, KeyShareExtensionParser> {

    public KeyShareExtensionParserTest() {
        super(
                KeyShareExtensionMessage.class,
                KeyShareExtensionParser::new,
                List.of(
                        Named.of(
                                "KeyShareExtensionMessage::getKeyShareListLength",
                                KeyShareExtensionMessage::getKeyShareListLength),
                        Named.of(
                                "KeyShareExtensionMessage::getKeyShareListBytes",
                                KeyShareExtensionMessage::getKeyShareListBytes)));
    }

    public static Stream<Arguments> provideTestVectors() {
        byte[] clientHybridEntry =
                hybridKeyShareEntry(NamedGroup.X25519_MLKEM768, ConnectionEndType.CLIENT);
        byte[] serverHybridEntry =
                hybridKeyShareEntry(NamedGroup.X25519_MLKEM768, ConnectionEndType.SERVER);
        byte[] serverLargeHybridEntry =
                hybridKeyShareEntry(NamedGroup.SECP384R1_MLKEM1024, ConnectionEndType.SERVER);

        return Stream.of(
                Arguments.of(
                        DataConverter.hexStringToByteArray(
                                "00330024001D00202a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c"),
                        List.of(ConnectionEndType.SERVER),
                        ExtensionType.KEY_SHARE,
                        38,
                        Arrays.asList(
                                null,
                                DataConverter.hexStringToByteArray(
                                        "001D00202a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c"))),
                Arguments.of(
                        clientExtensionBytes(clientHybridEntry),
                        List.of(ConnectionEndType.CLIENT),
                        ExtensionType.KEY_SHARE,
                        ExtensionByteLength.KEY_SHARE_LIST_LENGTH + clientHybridEntry.length,
                        Arrays.asList(clientHybridEntry.length, clientHybridEntry)),
                Arguments.of(
                        serverExtensionBytes(serverHybridEntry),
                        List.of(ConnectionEndType.SERVER),
                        ExtensionType.KEY_SHARE,
                        serverHybridEntry.length,
                        Arrays.asList(null, serverHybridEntry)),
                Arguments.of(
                        serverExtensionBytes(serverLargeHybridEntry),
                        List.of(ConnectionEndType.SERVER),
                        ExtensionType.KEY_SHARE,
                        serverLargeHybridEntry.length,
                        Arrays.asList(null, serverLargeHybridEntry)));
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
        byte[] keyShareList =
                DataConverter.concatenate(
                        DataConverter.intToBytes(
                                keyShareEntry.length, ExtensionByteLength.KEY_SHARE_LIST_LENGTH),
                        keyShareEntry);
        return extensionBytes(keyShareList);
    }

    private static byte[] serverExtensionBytes(byte[] keyShareEntry) {
        return extensionBytes(keyShareEntry);
    }

    private static byte[] extensionBytes(byte[] extensionPayload) {
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
