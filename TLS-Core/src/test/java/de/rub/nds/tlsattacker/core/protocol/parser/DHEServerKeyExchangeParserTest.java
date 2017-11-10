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
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class DHEServerKeyExchangeParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] {
                        {
                                ArrayConverter
                                        .hexStringToByteArray("0c00030b0100f64257b7087f081772a2bad6a942f305e8f95311394fb6f16eb94b3820da01a756a314e98f4055f3d007c6cb43a994adf74c648649f80c83bd65e917d4a1d350f8f5595fdc76524f3d3d8ddbce99e1579259cdfdb8ae744fc5fc76bc83c5473061ce7cc966ff15f9bbfd915ec701aad35b9e8da0a5723ad41af0bf4600582be5f488fd584e49dbcd20b49de49107366b336c380d451d0f7c88b31c7c5b2d8ef6f3c923c043f0a55b188d8ebb558cb85d38d334fd7c175743a31d186cde33212cb52aff3ce1b1294018118d7c84a70a72d686c40319c807297aca950cd9969fabd00a509b0246d3083d66a45d419f9c7cbd894b221926baaba25ec355e9320b3b0001020100312aa9863c13949bcd3e1b6bb18dabfc4fe185c0ee46f19298ee7169071b0f3248b089cab45937320875ebb44e70addd1f77d1b833036b826e9afff7c1826356ed577404a04f410a82d5ea1a66c29c24fb303f66debee871b6122e87fa3d2a6aab110459da87ef919571f5f5b76c850813d4a626ab8bbb33b6279e5b9ea3d0609ed6c52968d435124639fead8f214725b60280684e6d0e294c3ca380f37a6bbf1325bc48fe3f525f07e08030bcd027d3692e2c0967c4c27509df18cb9edbeff308094948e86a51835abebc7df9de0e63b0632674bbf55f1cd81f6d82a032561b996dd8744c6fd0808d67f762de43ed9a4a028fe31955004d2c989f93154af4a1060101006eb68609b1d1edb02a94880225b26bff071633c5cb2662a7bfe9f0062a97a3963922fddea69017bc9968b07e6e2fcc3c9158991df1ac6bf1d065ab8a7daa48bc41cce9a900d9e06567d858717f689722bb0c224c96fbef49721c9ae2b9ee2e44ca8d03bf5b4880e3c7163a05a3ec7613c394d1e9b405b77bf39ccd1da6c13a44631f557bbee497cfdb70efaccab6720510471964301aa5bba518f2190bc26a7f03ac2dd73be6484d47734853deefc6056a796f9ac547fcb01c279ae861168a5ca4aa5308248e8f84edd512a4bd6bc19840e0a248ca937b8feb593228da701e3651020191265fdb31f12850cdd73ad56de8b1ee131bf3202b5fce98c051eadc3b"),
                                HandshakeMessageType.SERVER_KEY_EXCHANGE,
                                779,
                                256,
                                ArrayConverter
                                        .hexStringToByteArray("f64257b7087f081772a2bad6a942f305e8f95311394fb6f16eb94b3820da01a756a314e98f4055f3d007c6cb43a994adf74c648649f80c83bd65e917d4a1d350f8f5595fdc76524f3d3d8ddbce99e1579259cdfdb8ae744fc5fc76bc83c5473061ce7cc966ff15f9bbfd915ec701aad35b9e8da0a5723ad41af0bf4600582be5f488fd584e49dbcd20b49de49107366b336c380d451d0f7c88b31c7c5b2d8ef6f3c923c043f0a55b188d8ebb558cb85d38d334fd7c175743a31d186cde33212cb52aff3ce1b1294018118d7c84a70a72d686c40319c807297aca950cd9969fabd00a509b0246d3083d66a45d419f9c7cbd894b221926baaba25ec355e9320b3b"),
                                1,
                                ArrayConverter.hexStringToByteArray("02"),
                                256,
                                ArrayConverter
                                        .hexStringToByteArray("312aa9863c13949bcd3e1b6bb18dabfc4fe185c0ee46f19298ee7169071b0f3248b089cab45937320875ebb44e70addd1f77d1b833036b826e9afff7c1826356ed577404a04f410a82d5ea1a66c29c24fb303f66debee871b6122e87fa3d2a6aab110459da87ef919571f5f5b76c850813d4a626ab8bbb33b6279e5b9ea3d0609ed6c52968d435124639fead8f214725b60280684e6d0e294c3ca380f37a6bbf1325bc48fe3f525f07e08030bcd027d3692e2c0967c4c27509df18cb9edbeff308094948e86a51835abebc7df9de0e63b0632674bbf55f1cd81f6d82a032561b996dd8744c6fd0808d67f762de43ed9a4a028fe31955004d2c989f93154af4a1"),
                                ArrayConverter.hexStringToByteArray("0601"),
                                256,
                                ArrayConverter
                                        .hexStringToByteArray("6eb68609b1d1edb02a94880225b26bff071633c5cb2662a7bfe9f0062a97a3963922fddea69017bc9968b07e6e2fcc3c9158991df1ac6bf1d065ab8a7daa48bc41cce9a900d9e06567d858717f689722bb0c224c96fbef49721c9ae2b9ee2e44ca8d03bf5b4880e3c7163a05a3ec7613c394d1e9b405b77bf39ccd1da6c13a44631f557bbee497cfdb70efaccab6720510471964301aa5bba518f2190bc26a7f03ac2dd73be6484d47734853deefc6056a796f9ac547fcb01c279ae861168a5ca4aa5308248e8f84edd512a4bd6bc19840e0a248ca937b8feb593228da701e3651020191265fdb31f12850cdd73ad56de8b1ee131bf3202b5fce98c051eadc3b"),
                                ProtocolVersion.TLS12 },
                        {
                                ArrayConverter
                                        .hexStringToByteArray("0c0003090100f64257b7087f081772a2bad6a942f305e8f95311394fb6f16eb94b3820da01a756a314e98f4055f3d007c6cb43a994adf74c648649f80c83bd65e917d4a1d350f8f5595fdc76524f3d3d8ddbce99e1579259cdfdb8ae744fc5fc76bc83c5473061ce7cc966ff15f9bbfd915ec701aad35b9e8da0a5723ad41af0bf4600582be5f488fd584e49dbcd20b49de49107366b336c380d451d0f7c88b31c7c5b2d8ef6f3c923c043f0a55b188d8ebb558cb85d38d334fd7c175743a31d186cde33212cb52aff3ce1b1294018118d7c84a70a72d686c40319c807297aca950cd9969fabd00a509b0246d3083d66a45d419f9c7cbd894b221926baaba25ec355e9320b3b0001020100b975fe56dae23e802dedf3ad0897e777580e3d85e60cad73f6fc725e6ab4af786916a076360447bdd43494eb0049fed7f875d267a42088a00089df5d2566a35fd2c879d8db10b2627a7ebdeeb0806902c41324ac51b810df00bcdffdfb90a76fa880ae4ba217c480e69bd54fab6c714a2576b39dd08eec49b64cd311cc2c6c3107ac4f307bba15be7e4efdfa5b23e2dace34f0d8a1005db0aaa62837fcb04b7f252034a8e8bebf6006ae7770b97c642e40a734e9914be4cc343075779595ac50e7551b22e8957994a9f5ad7f6c1c0bfd56822ec53831829d6516d34150cb2fff5c92019bfb4b1d866f908e8ead6e1cdc20761653d5296303c793e7644ce7a85a0100a0f082fe9a0842a81164be973bceb4c844ba07fd61d9f521ee557bccb45ab39e434ef22c1e2fcb939ba1373a7f3091c9e6c857977363bb8d01d6692344ee2b944bdc6e4766f6a1d68fec659e618476260e4c3f45d78476ba292abc8b5a68d5871fc5bda26f081e1c133560f76b7861ae93b0d650e98d786cbad15be844fe2550bc1f1285c3e02bef243d2e5964a38ac557edd2ddbada2d1eb311f86fb007a70d602286a0d9d19969c5ac68d679cded6591ffc486f83684a45431c097713450e0b2f1628fa049747f76153879e59492ef65d4f90407d314ed68681153d8a7b2a1b511086cd7d4d6e95131f757f94aeca22f3011dc1f2057b2f1e196ba91059890"),
                                HandshakeMessageType.SERVER_KEY_EXCHANGE,
                                777,
                                256,
                                ArrayConverter
                                        .hexStringToByteArray("f64257b7087f081772a2bad6a942f305e8f95311394fb6f16eb94b3820da01a756a314e98f4055f3d007c6cb43a994adf74c648649f80c83bd65e917d4a1d350f8f5595fdc76524f3d3d8ddbce99e1579259cdfdb8ae744fc5fc76bc83c5473061ce7cc966ff15f9bbfd915ec701aad35b9e8da0a5723ad41af0bf4600582be5f488fd584e49dbcd20b49de49107366b336c380d451d0f7c88b31c7c5b2d8ef6f3c923c043f0a55b188d8ebb558cb85d38d334fd7c175743a31d186cde33212cb52aff3ce1b1294018118d7c84a70a72d686c40319c807297aca950cd9969fabd00a509b0246d3083d66a45d419f9c7cbd894b221926baaba25ec355e9320b3b"),
                                1,
                                ArrayConverter.hexStringToByteArray("02"),
                                256,
                                ArrayConverter
                                        .hexStringToByteArray("b975fe56dae23e802dedf3ad0897e777580e3d85e60cad73f6fc725e6ab4af786916a076360447bdd43494eb0049fed7f875d267a42088a00089df5d2566a35fd2c879d8db10b2627a7ebdeeb0806902c41324ac51b810df00bcdffdfb90a76fa880ae4ba217c480e69bd54fab6c714a2576b39dd08eec49b64cd311cc2c6c3107ac4f307bba15be7e4efdfa5b23e2dace34f0d8a1005db0aaa62837fcb04b7f252034a8e8bebf6006ae7770b97c642e40a734e9914be4cc343075779595ac50e7551b22e8957994a9f5ad7f6c1c0bfd56822ec53831829d6516d34150cb2fff5c92019bfb4b1d866f908e8ead6e1cdc20761653d5296303c793e7644ce7a85a"),
                                null,
                                256,
                                ArrayConverter
                                        .hexStringToByteArray("a0f082fe9a0842a81164be973bceb4c844ba07fd61d9f521ee557bccb45ab39e434ef22c1e2fcb939ba1373a7f3091c9e6c857977363bb8d01d6692344ee2b944bdc6e4766f6a1d68fec659e618476260e4c3f45d78476ba292abc8b5a68d5871fc5bda26f081e1c133560f76b7861ae93b0d650e98d786cbad15be844fe2550bc1f1285c3e02bef243d2e5964a38ac557edd2ddbada2d1eb311f86fb007a70d602286a0d9d19969c5ac68d679cded6591ffc486f83684a45431c097713450e0b2f1628fa049747f76153879e59492ef65d4f90407d314ed68681153d8a7b2a1b511086cd7d4d6e95131f757f94aeca22f3011dc1f2057b2f1e196ba91059890"),
                                ProtocolVersion.TLS10 },
                        {
                                ArrayConverter
                                        .hexStringToByteArray("0c0003090100f64257b7087f081772a2bad6a942f305e8f95311394fb6f16eb94b3820da01a756a314e98f4055f3d007c6cb43a994adf74c648649f80c83bd65e917d4a1d350f8f5595fdc76524f3d3d8ddbce99e1579259cdfdb8ae744fc5fc76bc83c5473061ce7cc966ff15f9bbfd915ec701aad35b9e8da0a5723ad41af0bf4600582be5f488fd584e49dbcd20b49de49107366b336c380d451d0f7c88b31c7c5b2d8ef6f3c923c043f0a55b188d8ebb558cb85d38d334fd7c175743a31d186cde33212cb52aff3ce1b1294018118d7c84a70a72d686c40319c807297aca950cd9969fabd00a509b0246d3083d66a45d419f9c7cbd894b221926baaba25ec355e9320b3b00010201001e8cf176e5b4d911c48a037efd850f96af0d46ff24e2fa6cefce039a9224f57cd1d3404b67080926e56608b9a87ef633118d1ce20cfa4dcd7fd11bf37f21c30b0b32a27ef1a2fc9f7d31abbcbd4c8326e823589fe9e959e443eb89109fc2cfffcbb9548b82f2d9980d5cad247e165f09d2032bf4f3fef7e2cc69b612e1b2513204d889666ad3aca22cf551afb26daba72196bfeebeb15b3ca02d5f8eb95aa68d68cdbbb89213d457cdf2f6f55c77096ebaabfe022e69cb3694d8f4f98d5551b79a251c3e53e81998e8a1708452c3d088320506b9c2e05e4286c596d73e24cd00bbc5ebd9c3d48231caea82a555a27e2646418c36f93dfe439af6c5a43106b39a0100ec8b90e0e6aa384e0c59c16294bc0ca25d2d5f0e2c7fcd11f3d8190df87adefb854a8690e2ca6b6a9b33b4f5c747bc8283bb8c24e6a357e5f7019752877a93815a6ede463782ebb0be46285c9acc269cdfa5be35e14efe9b7f597a78c2dce3edb15a9900654191ea3f6e923437d4c98ed7b48e11aa443b21b60eee482c864376fb99d1e54bdd43de1e278918986f0334ca7b5060ec750def9d1698ee7b1216ea6eb7656a855ca279d7237c52afe9ee2c15916507293040afd9ef148ca3fb19e85ccfd3f50b1bc110e9190d721e4f389938c2166cd6a0cd7bfb157a13be6603ee03cb9676126ea6469f2edc3b5b3c3b39da2823b72e8a5f9b06824a43a14be18b"),
                                HandshakeMessageType.SERVER_KEY_EXCHANGE,
                                777,
                                256,
                                ArrayConverter
                                        .hexStringToByteArray("f64257b7087f081772a2bad6a942f305e8f95311394fb6f16eb94b3820da01a756a314e98f4055f3d007c6cb43a994adf74c648649f80c83bd65e917d4a1d350f8f5595fdc76524f3d3d8ddbce99e1579259cdfdb8ae744fc5fc76bc83c5473061ce7cc966ff15f9bbfd915ec701aad35b9e8da0a5723ad41af0bf4600582be5f488fd584e49dbcd20b49de49107366b336c380d451d0f7c88b31c7c5b2d8ef6f3c923c043f0a55b188d8ebb558cb85d38d334fd7c175743a31d186cde33212cb52aff3ce1b1294018118d7c84a70a72d686c40319c807297aca950cd9969fabd00a509b0246d3083d66a45d419f9c7cbd894b221926baaba25ec355e9320b3b"),
                                1,
                                ArrayConverter.hexStringToByteArray("02"),
                                256,
                                ArrayConverter
                                        .hexStringToByteArray("1e8cf176e5b4d911c48a037efd850f96af0d46ff24e2fa6cefce039a9224f57cd1d3404b67080926e56608b9a87ef633118d1ce20cfa4dcd7fd11bf37f21c30b0b32a27ef1a2fc9f7d31abbcbd4c8326e823589fe9e959e443eb89109fc2cfffcbb9548b82f2d9980d5cad247e165f09d2032bf4f3fef7e2cc69b612e1b2513204d889666ad3aca22cf551afb26daba72196bfeebeb15b3ca02d5f8eb95aa68d68cdbbb89213d457cdf2f6f55c77096ebaabfe022e69cb3694d8f4f98d5551b79a251c3e53e81998e8a1708452c3d088320506b9c2e05e4286c596d73e24cd00bbc5ebd9c3d48231caea82a555a27e2646418c36f93dfe439af6c5a43106b39a"),
                                null,
                                256,
                                ArrayConverter
                                        .hexStringToByteArray("ec8b90e0e6aa384e0c59c16294bc0ca25d2d5f0e2c7fcd11f3d8190df87adefb854a8690e2ca6b6a9b33b4f5c747bc8283bb8c24e6a357e5f7019752877a93815a6ede463782ebb0be46285c9acc269cdfa5be35e14efe9b7f597a78c2dce3edb15a9900654191ea3f6e923437d4c98ed7b48e11aa443b21b60eee482c864376fb99d1e54bdd43de1e278918986f0334ca7b5060ec750def9d1698ee7b1216ea6eb7656a855ca279d7237c52afe9ee2c15916507293040afd9ef148ca3fb19e85ccfd3f50b1bc110e9190d721e4f389938c2166cd6a0cd7bfb157a13be6603ee03cb9676126ea6469f2edc3b5b3c3b39da2823b72e8a5f9b06824a43a14be18b"),
                                ProtocolVersion.TLS11 }, });
    }

    private byte[] message;

    private HandshakeMessageType type;
    private int length;
    private int pLength;
    private byte[] p;
    private int gLength;
    private byte[] g;
    private int serializedKeyLength;
    private byte[] serializedKey;
    private byte[] signatureAndHashAlgo;
    private int sigLength;
    private byte[] signature;
    private ProtocolVersion version;

    public DHEServerKeyExchangeParserTest(byte[] message, HandshakeMessageType type, int length, int pLength, byte[] p,
            int gLength, byte[] g, int serializedKeyLength, byte[] serializedKey, byte[] signatureAndHashAlgo,
            int sigLength, byte[] signature, ProtocolVersion version) {
        this.message = message;
        this.type = type;
        this.length = length;
        this.pLength = pLength;
        this.p = p;
        this.gLength = gLength;
        this.g = g;
        this.serializedKeyLength = serializedKeyLength;
        this.serializedKey = serializedKey;
        this.signatureAndHashAlgo = signatureAndHashAlgo;
        this.sigLength = sigLength;
        this.signature = signature;
        this.version = version;
    }

    /**
     * Test of parse method, of class DHEServerKeyExchangeParser.
     */
    @Test
    public void testParse() {// TODO Write tests for others versions and make
                             // protocolversion a parameter
        DHEServerKeyExchangeParser<DHEServerKeyExchangeMessage> parser = new DHEServerKeyExchangeParser(0, message,
                version);
        DHEServerKeyExchangeMessage msg = parser.parse();
        assertArrayEquals(message, msg.getCompleteResultingMessage().getValue());
        assertTrue(msg.getLength().getValue() == length);
        assertTrue(msg.getType().getValue() == type.getValue());
        assertTrue(serializedKeyLength == msg.getPublicKeyLength().getValue());
        assertArrayEquals(serializedKey, msg.getPublicKey().getValue());
        byte[] tempSignatureAndHashAlgo = null;
        if (msg.getSignatureAndHashAlgorithm() != null && msg.getSignatureAndHashAlgorithm().getValue() != null) {
            tempSignatureAndHashAlgo = msg.getSignatureAndHashAlgorithm().getValue();
        }
        assertArrayEquals(signatureAndHashAlgo, tempSignatureAndHashAlgo);
        assertTrue(sigLength == msg.getSignatureLength().getValue());
        assertArrayEquals(signature, msg.getSignature().getValue());
    }

}
