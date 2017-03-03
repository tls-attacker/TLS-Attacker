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
import de.rub.nds.tlsattacker.tls.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.util.ArrayConverter;
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
                                .hexStringToByteArray("0c0002070100f64257b7087f081772a2bad6a942f305e8f95311394fb6f16eb94b3820da01a756a314e98f4055f3d007c6cb43a994adf74c648649f80c83bd65e917d4a1d350f8f5595fdc76524f3d3d8ddbce99e1579259cdfdb8ae744fc5fc76bc83c5473061ce7cc966ff15f9bbfd915ec701aad35b9e8da0a5723ad41af0bf4600582be5f488fd584e49dbcd20b49de49107366b336c380d451d0f7c88b31c7c5b2d8ef6f3c923c043f0a55b188d8ebb558cb85d38d334fd7c175743a31d186cde33212cb52aff3ce1b1294018118d7c84a70a72d686c40319c807297aca950cd9969fabd00a509b0246d3083d66a45d419f9c7cbd894b221926baaba25ec355e9320b3b0001020100e94af9e9d4bd213b3d1872c5313d611ddeaa368913b92c10f137090e7a3746db38c14e226b3e60abba2becc28e76916515b85ccb080104a8d98fd1d40a80a0eaa8e6b0e678204b8a5a985ab034a503fe1ca2cdce707cc62267d4abc377b43ae710190fa94cbbe0e8298abdcfc4a348ef9cfc11fd33602b9e3fc988e38dcb0d526aec687b3fa4b3bd536d82ad60cf65d225f6338f822915a88ca2c8e755cf1eaab14821956a669b54f5260718686898d994724d0c209b8c7e86e106bd21582ba5fb75ba18f5ee8946e3d94b98b515dcd8f0583428b83a68836869a9d4d1ac7e8942cbf5c11e2b1b52c9811eac51e30362fdb232eec857f8def940a4f0b622d259"),
                        0,
                        ArrayConverter
                                .hexStringToByteArray("0c0002070100f64257b7087f081772a2bad6a942f305e8f95311394fb6f16eb94b3820da01a756a314e98f4055f3d007c6cb43a994adf74c648649f80c83bd65e917d4a1d350f8f5595fdc76524f3d3d8ddbce99e1579259cdfdb8ae744fc5fc76bc83c5473061ce7cc966ff15f9bbfd915ec701aad35b9e8da0a5723ad41af0bf4600582be5f488fd584e49dbcd20b49de49107366b336c380d451d0f7c88b31c7c5b2d8ef6f3c923c043f0a55b188d8ebb558cb85d38d334fd7c175743a31d186cde33212cb52aff3ce1b1294018118d7c84a70a72d686c40319c807297aca950cd9969fabd00a509b0246d3083d66a45d419f9c7cbd894b221926baaba25ec355e9320b3b0001020100e94af9e9d4bd213b3d1872c5313d611ddeaa368913b92c10f137090e7a3746db38c14e226b3e60abba2becc28e76916515b85ccb080104a8d98fd1d40a80a0eaa8e6b0e678204b8a5a985ab034a503fe1ca2cdce707cc62267d4abc377b43ae710190fa94cbbe0e8298abdcfc4a348ef9cfc11fd33602b9e3fc988e38dcb0d526aec687b3fa4b3bd536d82ad60cf65d225f6338f822915a88ca2c8e755cf1eaab14821956a669b54f5260718686898d994724d0c209b8c7e86e106bd21582ba5fb75ba18f5ee8946e3d94b98b515dcd8f0583428b83a68836869a9d4d1ac7e8942cbf5c11e2b1b52c9811eac51e30362fdb232eec857f8def940a4f0b622d259"),
                        HandshakeMessageType.SERVER_KEY_EXCHANGE,
                        519,
                        0x0100,
                        ArrayConverter
                                .hexStringToByteArray("f64257b7087f081772a2bad6a942f305e8f95311394fb6f16eb94b3820da01a756a314e98f4055f3d007c6cb43a994adf74c648649f80c83bd65e917d4a1d350f8f5595fdc76524f3d3d8ddbce99e1579259cdfdb8ae744fc5fc76bc83c5473061ce7cc966ff15f9bbfd915ec701aad35b9e8da0a5723ad41af0bf4600582be5f488fd584e49dbcd20b49de49107366b336c380d451d0f7c88b31c7c5b2d8ef6f3c923c043f0a55b188d8ebb558cb85d38d334fd7c175743a31d186cde33212cb52aff3ce1b1294018118d7c84a70a72d686c40319c807297aca950cd9969fabd00a509b0246d3083d66a45d419f9c7cbd894b221926baaba25ec355e9320b3b"),0x0001,new byte[]{0x02},256,ArrayConverter.hexStringToByteArray("e94af9e9d4bd213b3d1872c5313d611ddeaa368913b92c10f137090e7a3746db38c14e226b3e60abba2becc28e76916515b85ccb080104a8d98fd1d40a80a0eaa8e6b0e678204b8a5a985ab034a503fe1ca2cdce707cc62267d4abc377b43ae710190fa94cbbe0e8298abdcfc4a348ef9cfc11fd33602b9e3fc988e38dcb0d526aec687b3fa4b3bd536d82ad60cf65d225f6338f822915a88ca2c8e755cf1eaab14821956a669b54f5260718686898d994724d0c209b8c7e86e106bd21582ba5fb75ba18f5ee8946e3d94b98b515dcd8f0583428b83a68836869a9d4d1ac7e8942cbf5c11e2b1b52c9811eac51e30362fdb232eec857f8def940a4f0b622d259") }, });
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

    public DHEServerKeyExchangeParserTest(byte[] message, int start, byte[] expectedPart, HandshakeMessageType type, int length, int pLength, byte[] p, int gLength, byte[] g, int serializedKeyLength, byte[] serializedKey) {
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
    }

    /**
     * Test of parse method, of class DHEServerKeyExchangeParser.
     */
    @Test
    public void testParse() {
        DHEServerKeyExchangeParser parser = new DHEServerKeyExchangeParser(start, message);
        DHEServerKeyExchangeMessage msg = parser.parse();
        assertArrayEquals(expectedPart, msg.getCompleteResultingMessage().getValue());
        assertTrue(msg.getLength().getValue() == length);
        assertTrue(msg.getType().getValue() == type.getValue());
        assertTrue(serializedKeyLength == msg.getSerializedPublicKeyLength().getValue());
        assertArrayEquals(serializedKey, msg.getSerializedPublicKey().getValue());

    }

}
