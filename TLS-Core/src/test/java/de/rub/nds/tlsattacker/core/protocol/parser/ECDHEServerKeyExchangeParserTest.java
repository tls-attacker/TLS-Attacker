/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class ECDHEServerKeyExchangeParserTest
        extends AbstractHandshakeMessageParserTest<
                ECDHEServerKeyExchangeMessage,
                ECDHEServerKeyExchangeParser<ECDHEServerKeyExchangeMessage>> {

    public ECDHEServerKeyExchangeParserTest() {
        super(
                ECDHEServerKeyExchangeMessage.class,
                ECDHEServerKeyExchangeParser::new,
                List.of(
                        Named.of(
                                "ECDHEServerKeyExchangeMessage::getGroupType",
                                ECDHEServerKeyExchangeMessage::getGroupType),
                        Named.of(
                                "ECDHEServerKeyExchangeMessage::getNamedGroup",
                                ECDHEServerKeyExchangeMessage::getNamedGroup),
                        Named.of(
                                "ServerKeyExchangeMessage::getPublicKeyLength",
                                ServerKeyExchangeMessage::getPublicKeyLength),
                        Named.of(
                                "ServerKeyExchangeMessage::getPublicKey",
                                ServerKeyExchangeMessage::getPublicKey),
                        Named.of(
                                "ServerKeyExchangeMessage::getSignatureAndHashAlgorithm",
                                ServerKeyExchangeMessage::getSignatureAndHashAlgorithm),
                        Named.of(
                                "ServerKeyExchangeMessage::getSignatureLength",
                                ServerKeyExchangeMessage::getSignatureLength),
                        Named.of(
                                "ServerKeyExchangeMessage::getSignature",
                                ServerKeyExchangeMessage::getSignature)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        ArrayConverter.hexStringToByteArray(
                                "0c0000900300174104a0da435d1657c12c86a3d232b2c94dfc11989074e5d5813cd46a6cbc63ade1b56dbacfb858c4a4e41188be99bb9d013aec89533b673d1b8d5784387dc0643544060300473045022100ca55fbccc20be69f6ed60d14c97a317efe2c36ba0eb2a6fc4428b83f2228ea14022036d5fc5aa9528b184e12ec628b018a314b7990f0fd894054833c04c093d2599e"),
                        List.of(
                                HandshakeMessageType.SERVER_KEY_EXCHANGE.getValue(),
                                144,
                                (byte) 0x03,
                                ArrayConverter.hexStringToByteArray("0017"),
                                65,
                                ArrayConverter.hexStringToByteArray(
                                        "04a0da435d1657c12c86a3d232b2c94dfc11989074e5d5813cd46a6cbc63ade1b56dbacfb858c4a4e41188be99bb9d013aec89533b673d1b8d5784387dc0643544"),
                                ArrayConverter.hexStringToByteArray("0603"),
                                71,
                                ArrayConverter.hexStringToByteArray(
                                        "3045022100ca55fbccc20be69f6ed60d14c97a317efe2c36ba0eb2a6fc4428b83f2228ea14022036d5fc5aa9528b184e12ec628b018a314b7990f0fd894054833c04c093d2599e"))),
                Arguments.of(
                        ProtocolVersion.TLS11,
                        ArrayConverter.hexStringToByteArray(
                                "0c000147030017410462989820753dec2474c1b2740b6c5e27a30b93ea0641983b8b40a6308c1b85a3430f573fd4100a2fe5874f4f4678001448a80c99963e659635b7068f32d6825a0100cd2c5bfbb7ea041d2999849cf3cf42aad8a0523de6e526225ebfc31e9cd9cdffd2063dd190ed2129f393ad4be30069fc38275b63d45486a25f855e413cfbad4387a74edac3b18b6f3a579fd646be6c21f27a270be0bc263dca0cbec495ab11e3ecea86d99b1242ffe964ac82b16eacda62d2a16cf0f10c79aa03a04ef8896e8ffe028ba991b6405b78bcb55a5cfe76a3af72a1497bb7bfed10654433f7ccc48dd4eac2411e060ccc79e21d0f91e40719ed5dba436fe12d75b910c853fb6b6b0d88d44e03c464062f1860748cc9bb2be1f60d26fd7a6966c7d3cd1624dd26d3a27ce1f3d56a6edb360e748aac041d1a3fd8161117e8a5673cd6c71df414d5b441"),
                        Arrays.asList(
                                HandshakeMessageType.SERVER_KEY_EXCHANGE.getValue(),
                                327,
                                (byte) 0x03,
                                ArrayConverter.hexStringToByteArray("0017"),
                                65,
                                ArrayConverter.hexStringToByteArray(
                                        "0462989820753dec2474c1b2740b6c5e27a30b93ea0641983b8b40a6308c1b85a3430f573fd4100a2fe5874f4f4678001448a80c99963e659635b7068f32d6825a"),
                                null,
                                256,
                                ArrayConverter.hexStringToByteArray(
                                        "cd2c5bfbb7ea041d2999849cf3cf42aad8a0523de6e526225ebfc31e9cd9cdffd2063dd190ed2129f393ad4be30069fc38275b63d45486a25f855e413cfbad4387a74edac3b18b6f3a579fd646be6c21f27a270be0bc263dca0cbec495ab11e3ecea86d99b1242ffe964ac82b16eacda62d2a16cf0f10c79aa03a04ef8896e8ffe028ba991b6405b78bcb55a5cfe76a3af72a1497bb7bfed10654433f7ccc48dd4eac2411e060ccc79e21d0f91e40719ed5dba436fe12d75b910c853fb6b6b0d88d44e03c464062f1860748cc9bb2be1f60d26fd7a6966c7d3cd1624dd26d3a27ce1f3d56a6edb360e748aac041d1a3fd8161117e8a5673cd6c71df414d5b441"))),
                Arguments.of(
                        ProtocolVersion.TLS10,
                        ArrayConverter.hexStringToByteArray(
                                "0c000147030017410462989820753dec2474c1b2740b6c5e27a30b93ea0641983b8b40a6308c1b85a3430f573fd4100a2fe5874f4f4678001448a80c99963e659635b7068f32d6825a0100afe942247469eb778cd0d979cabbeee237fe9de4d37dae2790f7ee5dc8e47b1187210217fe531b877f923850e972982bfca428ee73ed9d55f8b4b30f3869bf2c9d6e2d65961f06dbdcbcb04649ea1146c57746908c97f71982a702cfe56cb750ee157f0673b3acfb61aba25fe01e15e955975af64f7a85db4eadaedcb535c3450bf266da7022f00bf4cc017f4403b908de90bdcc36968837ba3f0891df24b8a7a93c74a3cbdc621e5b5a75b0485f8a156ca46c988bc9f88502a6a254bc08ceba610560633564866a7966c7743424c0f27ab2efaee8b524efb38b05712cb21b90ffc5e6061a5455fcdfda49ab9631da0c02a850b64d39cc9b134c362eb2a43520"),
                        Arrays.asList(
                                HandshakeMessageType.SERVER_KEY_EXCHANGE.getValue(),
                                327,
                                (byte) 0x03,
                                ArrayConverter.hexStringToByteArray("0017"),
                                65,
                                ArrayConverter.hexStringToByteArray(
                                        "0462989820753dec2474c1b2740b6c5e27a30b93ea0641983b8b40a6308c1b85a3430f573fd4100a2fe5874f4f4678001448a80c99963e659635b7068f32d6825a"),
                                null,
                                256,
                                ArrayConverter.hexStringToByteArray(
                                        "afe942247469eb778cd0d979cabbeee237fe9de4d37dae2790f7ee5dc8e47b1187210217fe531b877f923850e972982bfca428ee73ed9d55f8b4b30f3869bf2c9d6e2d65961f06dbdcbcb04649ea1146c57746908c97f71982a702cfe56cb750ee157f0673b3acfb61aba25fe01e15e955975af64f7a85db4eadaedcb535c3450bf266da7022f00bf4cc017f4403b908de90bdcc36968837ba3f0891df24b8a7a93c74a3cbdc621e5b5a75b0485f8a156ca46c988bc9f88502a6a254bc08ceba610560633564866a7966c7743424c0f27ab2efaee8b524efb38b05712cb21b90ffc5e6061a5455fcdfda49ab9631da0c02a850b64d39cc9b134c362eb2a43520"))));
    }
}
