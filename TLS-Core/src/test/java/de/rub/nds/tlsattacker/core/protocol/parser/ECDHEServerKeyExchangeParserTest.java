/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ECDHEServerKeyExchangeParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] {
                        {
                                ArrayConverter
                                        .hexStringToByteArray("0c0000900300174104a0da435d1657c12c86a3d232b2c94dfc11989074e5d5813cd46a6cbc63ade1b56dbacfb858c4a4e41188be99bb9d013aec89533b673d1b8d5784387dc0643544060300473045022100ca55fbccc20be69f6ed60d14c97a317efe2c36ba0eb2a6fc4428b83f2228ea14022036d5fc5aa9528b184e12ec628b018a314b7990f0fd894054833c04c093d2599e"),
                                HandshakeMessageType.SERVER_KEY_EXCHANGE,
                                144,
                                (byte) 0x03,
                                ArrayConverter.hexStringToByteArray("0017"),
                                65,
                                ArrayConverter
                                        .hexStringToByteArray("04a0da435d1657c12c86a3d232b2c94dfc11989074e5d5813cd46a6cbc63ade1b56dbacfb858c4a4e41188be99bb9d013aec89533b673d1b8d5784387dc0643544"),
                                ArrayConverter.hexStringToByteArray("0603"),
                                71,
                                ArrayConverter
                                        .hexStringToByteArray("3045022100ca55fbccc20be69f6ed60d14c97a317efe2c36ba0eb2a6fc4428b83f2228ea14022036d5fc5aa9528b184e12ec628b018a314b7990f0fd894054833c04c093d2599e"),
                                ProtocolVersion.TLS12 },
                        {
                                ArrayConverter
                                        .hexStringToByteArray("0c000147030017410462989820753dec2474c1b2740b6c5e27a30b93ea0641983b8b40a6308c1b85a3430f573fd4100a2fe5874f4f4678001448a80c99963e659635b7068f32d6825a0100cd2c5bfbb7ea041d2999849cf3cf42aad8a0523de6e526225ebfc31e9cd9cdffd2063dd190ed2129f393ad4be30069fc38275b63d45486a25f855e413cfbad4387a74edac3b18b6f3a579fd646be6c21f27a270be0bc263dca0cbec495ab11e3ecea86d99b1242ffe964ac82b16eacda62d2a16cf0f10c79aa03a04ef8896e8ffe028ba991b6405b78bcb55a5cfe76a3af72a1497bb7bfed10654433f7ccc48dd4eac2411e060ccc79e21d0f91e40719ed5dba436fe12d75b910c853fb6b6b0d88d44e03c464062f1860748cc9bb2be1f60d26fd7a6966c7d3cd1624dd26d3a27ce1f3d56a6edb360e748aac041d1a3fd8161117e8a5673cd6c71df414d5b441"),
                                HandshakeMessageType.SERVER_KEY_EXCHANGE,
                                327,
                                (byte) 0x03,
                                ArrayConverter.hexStringToByteArray("0017"),
                                65,
                                ArrayConverter
                                        .hexStringToByteArray("0462989820753dec2474c1b2740b6c5e27a30b93ea0641983b8b40a6308c1b85a3430f573fd4100a2fe5874f4f4678001448a80c99963e659635b7068f32d6825a"),
                                null,
                                256,
                                ArrayConverter
                                        .hexStringToByteArray("cd2c5bfbb7ea041d2999849cf3cf42aad8a0523de6e526225ebfc31e9cd9cdffd2063dd190ed2129f393ad4be30069fc38275b63d45486a25f855e413cfbad4387a74edac3b18b6f3a579fd646be6c21f27a270be0bc263dca0cbec495ab11e3ecea86d99b1242ffe964ac82b16eacda62d2a16cf0f10c79aa03a04ef8896e8ffe028ba991b6405b78bcb55a5cfe76a3af72a1497bb7bfed10654433f7ccc48dd4eac2411e060ccc79e21d0f91e40719ed5dba436fe12d75b910c853fb6b6b0d88d44e03c464062f1860748cc9bb2be1f60d26fd7a6966c7d3cd1624dd26d3a27ce1f3d56a6edb360e748aac041d1a3fd8161117e8a5673cd6c71df414d5b441"),
                                ProtocolVersion.TLS11 },
                        {
                                ArrayConverter
                                        .hexStringToByteArray("0c000147030017410462989820753dec2474c1b2740b6c5e27a30b93ea0641983b8b40a6308c1b85a3430f573fd4100a2fe5874f4f4678001448a80c99963e659635b7068f32d6825a0100afe942247469eb778cd0d979cabbeee237fe9de4d37dae2790f7ee5dc8e47b1187210217fe531b877f923850e972982bfca428ee73ed9d55f8b4b30f3869bf2c9d6e2d65961f06dbdcbcb04649ea1146c57746908c97f71982a702cfe56cb750ee157f0673b3acfb61aba25fe01e15e955975af64f7a85db4eadaedcb535c3450bf266da7022f00bf4cc017f4403b908de90bdcc36968837ba3f0891df24b8a7a93c74a3cbdc621e5b5a75b0485f8a156ca46c988bc9f88502a6a254bc08ceba610560633564866a7966c7743424c0f27ab2efaee8b524efb38b05712cb21b90ffc5e6061a5455fcdfda49ab9631da0c02a850b64d39cc9b134c362eb2a43520"),
                                HandshakeMessageType.SERVER_KEY_EXCHANGE,
                                327,
                                (byte) 0x03,
                                ArrayConverter.hexStringToByteArray("0017"),
                                65,
                                ArrayConverter
                                        .hexStringToByteArray("0462989820753dec2474c1b2740b6c5e27a30b93ea0641983b8b40a6308c1b85a3430f573fd4100a2fe5874f4f4678001448a80c99963e659635b7068f32d6825a"),
                                null,
                                256,
                                ArrayConverter
                                        .hexStringToByteArray("afe942247469eb778cd0d979cabbeee237fe9de4d37dae2790f7ee5dc8e47b1187210217fe531b877f923850e972982bfca428ee73ed9d55f8b4b30f3869bf2c9d6e2d65961f06dbdcbcb04649ea1146c57746908c97f71982a702cfe56cb750ee157f0673b3acfb61aba25fe01e15e955975af64f7a85db4eadaedcb535c3450bf266da7022f00bf4cc017f4403b908de90bdcc36968837ba3f0891df24b8a7a93c74a3cbdc621e5b5a75b0485f8a156ca46c988bc9f88502a6a254bc08ceba610560633564866a7966c7743424c0f27ab2efaee8b524efb38b05712cb21b90ffc5e6061a5455fcdfda49ab9631da0c02a850b64d39cc9b134c362eb2a43520"),
                                ProtocolVersion.TLS10 } });
    }

    private byte[] message;

    private HandshakeMessageType type;
    private int length;
    private byte curveType;
    private byte[] namedCurve;
    private int pubKeyLength;
    private byte[] pubKey;
    private byte[] signatureAndHashAlgo;
    private int sigLength;
    private byte[] signature;
    private ProtocolVersion version;

    public ECDHEServerKeyExchangeParserTest(byte[] message, HandshakeMessageType type, int length, byte curveType,
            byte[] namedCurve, int pubKeyLength, byte[] pubKey, byte[] signatureAndHashAlgo, int sigLength,
            byte[] signature, ProtocolVersion version) {
        this.message = message;
        this.type = type;
        this.length = length;
        this.curveType = curveType;
        this.namedCurve = namedCurve;
        this.pubKeyLength = pubKeyLength;
        this.pubKey = pubKey;
        this.signatureAndHashAlgo = signatureAndHashAlgo;
        this.sigLength = sigLength;
        this.signature = signature;
        this.version = version;
    }

    /**
     * Test of parse method, of class ECDHEServerKeyExchangeParser.
     */
    @Test
    public void testParse() {// TODO make protocolversion a parameter and test
                             // for other versions too
        ECDHEServerKeyExchangeParser<ECDHEServerKeyExchangeMessage> parser = new ECDHEServerKeyExchangeParser(0,
                message, version);
        ECDHEServerKeyExchangeMessage msg = parser.parse();
        assertArrayEquals(message, msg.getCompleteResultingMessage().getValue());
        assertTrue(length == msg.getLength().getValue());
        assertTrue(type.getValue() == msg.getType().getValue());
        assertTrue(curveType == msg.getGroupType().getValue());
        assertArrayEquals(namedCurve, msg.getNamedGroup().getValue());
        assertTrue(pubKeyLength == msg.getPublicKeyLength().getValue());
        assertArrayEquals(pubKey, msg.getPublicKey().getValue());
        byte[] tempSignatureAndHashAlgo = null;
        if (msg.getSignatureAndHashAlgorithm() != null && msg.getSignatureAndHashAlgorithm().getValue() != null) {
            tempSignatureAndHashAlgo = msg.getSignatureAndHashAlgorithm().getValue();
        }
        assertArrayEquals(signatureAndHashAlgo, tempSignatureAndHashAlgo);
        assertTrue(sigLength == msg.getSignatureLength().getValue());
        assertArrayEquals(signature, msg.getSignature().getValue());
    }
}
