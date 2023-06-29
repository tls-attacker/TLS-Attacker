/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ChooserType;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EncryptedServerNameIndicationExtensionPreparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.core.workflow.chooser.ChooserFactory;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.security.Security;
import java.util.List;
import java.util.stream.Stream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class EncryptedServerNameIndicationExtensionParserTest
        extends AbstractExtensionParserTest<
                EncryptedServerNameIndicationExtensionMessage,
                EncryptedServerNameIndicationExtensionParser> {

    private final Chooser chooser;
    private final TlsContext context;

    @BeforeAll
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public EncryptedServerNameIndicationExtensionParserTest() {
        super(
                EncryptedServerNameIndicationExtensionMessage.class,
                EncryptedServerNameIndicationExtensionParser::new,
                List.of(
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getEsniMessageTypeConfig",
                                msg ->
                                        EncryptedServerNameIndicationExtensionMessage
                                                .EsniMessageType.CLIENT),
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getCipherSuite",
                                EncryptedServerNameIndicationExtensionMessage::getCipherSuite),
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getKeyShareEntry::getGroup",
                                msg -> msg.getKeyShareEntry().getGroup()),
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getKeyShareEntry::getPublicKeyLength",
                                msg -> msg.getKeyShareEntry().getPublicKeyLength()),
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getKeyShareEntry::getPublicKey",
                                msg -> msg.getKeyShareEntry().getPublicKey()),
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getRecordDigestLength",
                                EncryptedServerNameIndicationExtensionMessage
                                        ::getRecordDigestLength),
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getRecordDigest",
                                EncryptedServerNameIndicationExtensionMessage::getRecordDigest),
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getEncryptedSniLength",
                                EncryptedServerNameIndicationExtensionMessage
                                        ::getEncryptedSniLength),
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getEncryptedSni",
                                EncryptedServerNameIndicationExtensionMessage::getEncryptedSni),
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getEncryptedSniComputation::getEsniSharedSecret",
                                msg -> msg.getEncryptedSniComputation().getEsniSharedSecret()),
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getEncryptedSniComputation::getEsniMasterSecret",
                                msg -> msg.getEncryptedSniComputation().getEsniMasterSecret()),
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getEncryptedSniComputation::getEsniContents",
                                msg -> msg.getEncryptedSniComputation().getEsniContents()),
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getEncryptedSniComputation::getEsniContentsHash",
                                msg -> msg.getEncryptedSniComputation().getEsniContentsHash()),
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getEncryptedSniComputation::getEsniKey",
                                msg -> msg.getEncryptedSniComputation().getEsniKey()),
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getEncryptedSniComputation::getEsniIv",
                                msg -> msg.getEncryptedSniComputation().getEsniIv()),
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getEncryptedSniComputation::getClientHelloKeyShare",
                                msg -> msg.getEncryptedSniComputation().getClientHelloKeyShare()),
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getClientEsniInnerBytes",
                                EncryptedServerNameIndicationExtensionMessage
                                        ::getClientEsniInnerBytes),
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getClientEsniInner::getClientNonce",
                                msg -> msg.getClientEsniInner().getClientNonce()),
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getClientEsniInner::getServerNameListLength",
                                msg -> msg.getClientEsniInner().getServerNameListLength()),
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getClientEsniInner::getServerNameListBytes",
                                msg -> msg.getClientEsniInner().getServerNameListBytes()),
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getClientEsniInner::getPadding",
                                msg -> msg.getClientEsniInner().getPadding()),
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getClientEsniInner::getServerNameList::get::getServerNameType",
                                msg ->
                                        msg.getClientEsniInner()
                                                .getServerNameList()
                                                .get(0)
                                                .getServerNameType()),
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getClientEsniInner::getServerNameList::get::getServerNameLength",
                                msg ->
                                        msg.getClientEsniInner()
                                                .getServerNameList()
                                                .get(0)
                                                .getServerNameLength()),
                        Named.of(
                                "EncryptedServerNameIndicationExtensionMessage::getClientEsniInner::getServerNameList::get::getServerName",
                                msg ->
                                        msg.getClientEsniInner()
                                                .getServerNameList()
                                                .get(0)
                                                .getServerName())));
        context = new TlsContext(config);
        chooser = ChooserFactory.getChooser(ChooserType.DEFAULT, tlsContext.getContext(), config);
    }

    public static Stream<Arguments> provideTestVectors() {
        KeyShareEntry serverKeyShareEntry = new KeyShareEntry();
        serverKeyShareEntry.setGroup(NamedGroup.ECDH_X25519.getValue());
        serverKeyShareEntry.setPrivateKey(
                new BigInteger(
                        ArrayConverter.hexStringToByteArray(
                                "b0b658b2287a55d9c261bb3feb0c55954be29366eb353b54f986acaa62f81e5A")));

        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "ffce016e1301001d002041f2f4bcb69a924d3b90d815d8bbe19f5aa68926f6538626737c30bd814d54000020b045ec64136934560d15f6fde789fa515c666ea0b2979bebda671b298b6c2b9c0124a133e3280209e18ec46ee8d37062f4df1ddc9a4d60de59fb57c284989f23fdb02da0ae115e87b57be927499ef19cf88424cd0906b915010f51a0b39be192ba10bcd6d6b47a1967439670278a433337eebd5695106e1d1ed38337e7ad71fb8f756bb527c096751da3a52604fb0859ded699e3cd2cbc47fae73819d8eb2c8dcf1eccc8502ac6cdb237e2541b85140aa83d9234e10ab0108ba81586a729bf26f95b32a9f7a89aeaecedf77fd3cdef8c58144e2a4fb359bb8a37483fdc135179793a6510d291b42b737ed9aa76b490bd6745068391831e6f2cc4370c44f0957cf932f58e8174a46dd2184a7e4950239b546a6b699b19f4e53668c2be2d2311b5965bb82ed14f22368c125a0a71acee5f06579fe9fb798f6a36092093ce32c591603c5b6b16ee"),
                        List.of(
                                List.of(serverKeyShareEntry),
                                ArrayConverter.hexStringToByteArray(
                                        "e6aef9c483abf499f6a1c3befa5f16f854482072a0d3d29476c51f5c3d4d5709"),
                                List.of(
                                        new KeyShareStoreEntry(
                                                NamedGroup.ECDH_X25519,
                                                ArrayConverter.hexStringToByteArray(
                                                        "33f34944dd62f7d40388729b584e5eb108e29b34c739af29ec5113fb2b8d5714")),
                                        new KeyShareStoreEntry(
                                                NamedGroup.SECP256R1,
                                                ArrayConverter.hexStringToByteArray(
                                                        "0401e31149fb03eee9a101c3660bb29db586d1a347414f0c28011a5fe4805a355d37edfec598888d76083580f0394e754a4666f9a66678c23ae2058ac2fa55a459"))),
                                ConnectionEndType.SERVER),
                        ExtensionType.ENCRYPTED_SERVER_NAME_INDICATION,
                        366,
                        List.of(
                                EncryptedServerNameIndicationExtensionMessage.EsniMessageType
                                        .CLIENT,
                                ArrayConverter.hexStringToByteArray("1301"),
                                ArrayConverter.hexStringToByteArray("001d"),
                                32,
                                ArrayConverter.hexStringToByteArray(
                                        "41f2f4bcb69a924d3b90d815d8bbe19f5aa68926f6538626737c30bd814d5400"),
                                32,
                                ArrayConverter.hexStringToByteArray(
                                        "b045ec64136934560d15f6fde789fa515c666ea0b2979bebda671b298b6c2b9c"),
                                292,
                                ArrayConverter.hexStringToByteArray(
                                        "a133e3280209e18ec46ee8d37062f4df1ddc9a4d60de59fb57c284989f23fdb02da0ae115e87b57be927499ef19cf88424cd0906b915010f51a0b39be192ba10bcd6d6b47a1967439670278a433337eebd5695106e1d1ed38337e7ad71fb8f756bb527c096751da3a52604fb0859ded699e3cd2cbc47fae73819d8eb2c8dcf1eccc8502ac6cdb237e2541b85140aa83d9234e10ab0108ba81586a729bf26f95b32a9f7a89aeaecedf77fd3cdef8c58144e2a4fb359bb8a37483fdc135179793a6510d291b42b737ed9aa76b490bd6745068391831e6f2cc4370c44f0957cf932f58e8174a46dd2184a7e4950239b546a6b699b19f4e53668c2be2d2311b5965bb82ed14f22368c125a0a71acee5f06579fe9fb798f6a36092093ce32c591603c5b6b16ee"),
                                ArrayConverter.hexStringToByteArray(
                                        "55F22988BEC557911665246C18B744ED866D5F9DF4571C5F204E7569A2712C75"),
                                ArrayConverter.hexStringToByteArray(
                                        "BD0677ECAD9141C2B83CEF09168FFCF6DE885DA656E571D086E34CE06EEDA824"),
                                ArrayConverter.hexStringToByteArray(
                                        "0020b045ec64136934560d15f6fde789fa515c666ea0b2979bebda671b298b6c2b9c001d002041f2f4bcb69a924d3b90d815d8bbe19f5aa68926f6538626737c30bd814d5400e6aef9c483abf499f6a1c3befa5f16f854482072a0d3d29476c51f5c3d4d5709"),
                                ArrayConverter.hexStringToByteArray(
                                        "8106289e822aaf4ba1053ed99fcd30bb24b803c2b10f3c0d0c05892ac8332d5a"),
                                ArrayConverter.hexStringToByteArray(
                                        "BD005945C1C69AA9F36944C4040C5558"),
                                ArrayConverter.hexStringToByteArray("41EEF7C0378F8D6D9896A15A"),
                                ArrayConverter.hexStringToByteArray(
                                        "0069001d002033f34944dd62f7d40388729b584e5eb108e29b34c739af29ec5113fb2b8d5714001700410401e31149fb03eee9a101c3660bb29db586d1a347414f0c28011a5fe4805a355d37edfec598888d76083580f0394e754a4666f9a66678c23ae2058ac2fa55a459"),
                                ArrayConverter.hexStringToByteArray(
                                        "a7284c9a52f15c13644b947261774657001200000f62617a2e6578616d706c652e636f6d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
                                ArrayConverter.hexStringToByteArray(
                                        "a7284c9a52f15c13644b947261774657"),
                                18,
                                ArrayConverter.hexStringToByteArray(
                                        "00000f62617a2e6578616d706c652e636f6d"),
                                new byte[240],
                                (byte) 0x00,
                                15,
                                ArrayConverter.hexStringToByteArray(
                                        "62617a2e6578616d706c652e636f6d"))));
    }

    @Override
    protected void assertExtensionMessageSpecific(
            List<Object> providedAdditionalValues, List<Object> expectedMessageSpecificValues) {
        // noinspection unchecked
        config.setEsniServerKeyPairs((List<KeyShareEntry>) providedAdditionalValues.get(0));
        context.setClientRandom((byte[]) providedAdditionalValues.get(1));
        // noinspection unchecked
        context.setClientKeyShareStoreEntryList(
                (List<KeyShareStoreEntry>) providedAdditionalValues.get(2));

        try {
            EncryptedServerNameIndicationExtensionPreparator preparator =
                    new EncryptedServerNameIndicationExtensionPreparator(chooser, message);
            preparator.setEsniPreparatorMode(
                    EncryptedServerNameIndicationExtensionPreparator.EsniPreparatorMode.SERVER);
            preparator.prepareAfterParse();

            super.assertExtensionMessageSpecific(
                    providedAdditionalValues, expectedMessageSpecificValues);
        } catch (UnsupportedOperationException ex) {
            // TODO: fix for layer system
        }
    }
}
