/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.modifiablevariable.util.ArrayConverter;
import java.util.Arrays;
import java.util.Collection;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
@RunWith(Parameterized.class)
public class DHEServerKeyExchangeParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] { {
                        ArrayConverter
                                .hexStringToByteArray("0c00030b0100f64257b7087f081772a2bad6a942f305e8f95311394fb6f16eb94b3820da01a756a314e98f4055f3d007c6cb43a994adf74c648649f80c83bd65e917d4a1d350f8f5595fdc76524f3d3d8ddbce99e1579259cdfdb8ae744fc5fc76bc83c5473061ce7cc966ff15f9bbfd915ec701aad35b9e8da0a5723ad41af0bf4600582be5f488fd584e49dbcd20b49de49107366b336c380d451d0f7c88b31c7c5b2d8ef6f3c923c043f0a55b188d8ebb558cb85d38d334fd7c175743a31d186cde33212cb52aff3ce1b1294018118d7c84a70a72d686c40319c807297aca950cd9969fabd00a509b0246d3083d66a45d419f9c7cbd894b221926baaba25ec355e9320b3b0001020100312aa9863c13949bcd3e1b6bb18dabfc4fe185c0ee46f19298ee7169071b0f3248b089cab45937320875ebb44e70addd1f77d1b833036b826e9afff7c1826356ed577404a04f410a82d5ea1a66c29c24fb303f66debee871b6122e87fa3d2a6aab110459da87ef919571f5f5b76c850813d4a626ab8bbb33b6279e5b9ea3d0609ed6c52968d435124639fead8f214725b60280684e6d0e294c3ca380f37a6bbf1325bc48fe3f525f07e08030bcd027d3692e2c0967c4c27509df18cb9edbeff308094948e86a51835abebc7df9de0e63b0632674bbf55f1cd81f6d82a032561b996dd8744c6fd0808d67f762de43ed9a4a028fe31955004d2c989f93154af4a1060101006eb68609b1d1edb02a94880225b26bff071633c5cb2662a7bfe9f0062a97a3963922fddea69017bc9968b07e6e2fcc3c9158991df1ac6bf1d065ab8a7daa48bc41cce9a900d9e06567d858717f689722bb0c224c96fbef49721c9ae2b9ee2e44ca8d03bf5b4880e3c7163a05a3ec7613c394d1e9b405b77bf39ccd1da6c13a44631f557bbee497cfdb70efaccab6720510471964301aa5bba518f2190bc26a7f03ac2dd73be6484d47734853deefc6056a796f9ac547fcb01c279ae861168a5ca4aa5308248e8f84edd512a4bd6bc19840e0a248ca937b8feb593228da701e3651020191265fdb31f12850cdd73ad56de8b1ee131bf3202b5fce98c051eadc3b"),
                        0,
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
                        (byte) 0x06,
                        (byte) 0x01,
                        256,
                        ArrayConverter
                                .hexStringToByteArray("6eb68609b1d1edb02a94880225b26bff071633c5cb2662a7bfe9f0062a97a3963922fddea69017bc9968b07e6e2fcc3c9158991df1ac6bf1d065ab8a7daa48bc41cce9a900d9e06567d858717f689722bb0c224c96fbef49721c9ae2b9ee2e44ca8d03bf5b4880e3c7163a05a3ec7613c394d1e9b405b77bf39ccd1da6c13a44631f557bbee497cfdb70efaccab6720510471964301aa5bba518f2190bc26a7f03ac2dd73be6484d47734853deefc6056a796f9ac547fcb01c279ae861168a5ca4aa5308248e8f84edd512a4bd6bc19840e0a248ca937b8feb593228da701e3651020191265fdb31f12850cdd73ad56de8b1ee131bf3202b5fce98c051eadc3b") } });
    }

    private byte[] message;
    private int start;
    private byte[] expectedPart;

    private HandshakeMessageType type;
    private int length;
    private int pLength;
    private byte[] p;
    private int gLength;
    private byte[] g;
    private int serializedKeyLength;
    private byte[] serializedKey;
    private byte hashAlgo;
    private byte sigAlgo;
    private int sigLength;
    private byte[] signature;

    public DHEServerKeyExchangeParserTest(byte[] message, int start, byte[] expectedPart, HandshakeMessageType type,
            int length, int pLength, byte[] p, int gLength, byte[] g, int serializedKeyLength, byte[] serializedKey,
            byte hashAlgo, byte sigAlgo, int sigLength, byte[] signature) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.type = type;
        this.length = length;
        this.pLength = pLength;
        this.p = p;
        this.gLength = gLength;
        this.g = g;
        this.serializedKeyLength = serializedKeyLength;
        this.serializedKey = serializedKey;
        this.hashAlgo = hashAlgo;
        this.sigAlgo = sigAlgo;
        this.sigLength = sigLength;
        this.signature = signature;
    }

    /**
     * Test of parse method, of class DHEServerKeyExchangeParser.
     */
    @Test
    public void testParse() {// TODO Write tests for others versions and make
                             // protocolversion a parameter
        DHEServerKeyExchangeParser parser = new DHEServerKeyExchangeParser(start, message, ProtocolVersion.TLS12);
        DHEServerKeyExchangeMessage msg = parser.parse();
        assertArrayEquals(expectedPart, msg.getCompleteResultingMessage().getValue());
        assertTrue(msg.getLength().getValue() == length);
        assertTrue(msg.getType().getValue() == type.getValue());
        assertTrue(serializedKeyLength == msg.getSerializedPublicKeyLength().getValue());
        assertArrayEquals(serializedKey, msg.getSerializedPublicKey().getValue());
        assertTrue(hashAlgo == msg.getHashAlgorithm().getValue());
        assertTrue(sigAlgo == msg.getSignatureAlgorithm().getValue());
        assertTrue(sigLength == msg.getSignatureLength().getValue());
        assertArrayEquals(signature, msg.getSignature().getValue());
    }

}
