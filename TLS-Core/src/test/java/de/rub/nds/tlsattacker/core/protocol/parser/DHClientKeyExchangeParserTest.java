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
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class DHClientKeyExchangeParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] {
                        {
                                ArrayConverter
                                        .hexStringToByteArray("100001020100c2bf1e41e5f67a882cd9b0150edbeb95d982fb97a0a0732739d96ac5af92bfeaeb7040419a7be326fd1a43f02fd264cd58d95d0a4f9b81636bae126b50863c49cb386e23a8f2a51c8b272fa2f5321cfce4dbff6fc6e769246f887007434d2e6315edaf2fcc8d66f9f42c67ff08cd4fde092dece15656035a9dd1aedb0091dbae42b1501306c21cedb5c63858456b1f01484c3df3f0a6871070212d9448849e1057f4257917aa3bcb9287b2b4e4eaa6c8c4f49d3c737259c22b68dc6eb6288a09ddf70a5bf4348ebd96e411ef496a3d478b0e3fd07ff29be6d1b246e0086793b9036df0a39cae63e1647fef812c36766dda2de62154c11b5eb216e8bd813cb71d"),
                                HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                                258,
                                256,
                                ArrayConverter
                                        .hexStringToByteArray("c2bf1e41e5f67a882cd9b0150edbeb95d982fb97a0a0732739d96ac5af92bfeaeb7040419a7be326fd1a43f02fd264cd58d95d0a4f9b81636bae126b50863c49cb386e23a8f2a51c8b272fa2f5321cfce4dbff6fc6e769246f887007434d2e6315edaf2fcc8d66f9f42c67ff08cd4fde092dece15656035a9dd1aedb0091dbae42b1501306c21cedb5c63858456b1f01484c3df3f0a6871070212d9448849e1057f4257917aa3bcb9287b2b4e4eaa6c8c4f49d3c737259c22b68dc6eb6288a09ddf70a5bf4348ebd96e411ef496a3d478b0e3fd07ff29be6d1b246e0086793b9036df0a39cae63e1647fef812c36766dda2de62154c11b5eb216e8bd813cb71d"),
                                ProtocolVersion.TLS12 },
                        {
                                ArrayConverter
                                        .hexStringToByteArray("10000102010038fb270745bc9de4bae029342f8341460798d63986f606c98fced943ea8b695c193371edeec1aac4f978aa703b8aa79d18826e54fb1b0c6136366f52ea53d80aea9837f37537a6fbc1bf08dfad23f8c2072d82458eee4ecd6ecf9b7381e44f4d4a251599e8a8a0346c94b1ff611aac65088959b30cd8df5eeb96942c1f27257204436693980fb9dd839b28a0e6f347a2aa56f981d541ca38b45227df0b42396287566060a32fd3483413db32ef15ae1123e35897819053fa9a08127438cf27965d8b8317aac5c48823eb0bed3c4dac2becbf57a606570321f230fdac5f0a39443be2844e940bf21411d521c44e82e1fc1fd2c000dad68e34aa5e035053a2c4b0"),
                                HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                                258,
                                256,
                                ArrayConverter
                                        .hexStringToByteArray("38fb270745bc9de4bae029342f8341460798d63986f606c98fced943ea8b695c193371edeec1aac4f978aa703b8aa79d18826e54fb1b0c6136366f52ea53d80aea9837f37537a6fbc1bf08dfad23f8c2072d82458eee4ecd6ecf9b7381e44f4d4a251599e8a8a0346c94b1ff611aac65088959b30cd8df5eeb96942c1f27257204436693980fb9dd839b28a0e6f347a2aa56f981d541ca38b45227df0b42396287566060a32fd3483413db32ef15ae1123e35897819053fa9a08127438cf27965d8b8317aac5c48823eb0bed3c4dac2becbf57a606570321f230fdac5f0a39443be2844e940bf21411d521c44e82e1fc1fd2c000dad68e34aa5e035053a2c4b0"),
                                ProtocolVersion.TLS11 },
                        {
                                ArrayConverter
                                        .hexStringToByteArray("1000010201006dd24d6dcce4b6ad0231bee56cf767fc06f05a03d5921093e70e79c0d885a2736dd646bdfdded6e3c1e5c6abcb7157418e8389085f83f68c3cf746004a55fa008ec8446200bf5031678abfd900841f6be1e68ed76335f59e1611244900f7c5ae3151f42739c28546be76c4ce476218b11e7b41cad7512fafe2c477e271878b83fd071b34e12f3f5ef5f36cf797d584fe104392f9444c4edbcc3f500bdf7c8ee7ce8aba60f2a857ab4668c9096a56c393e17cd04f0830a064827c16df35612720859802bf40f99879392231a38cf647464057cdfd98a13887d638503093688a5ab72dcb54f83922e685a694b6755df3ffabee778014b30883c284cb6af269b573"),
                                HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                                258,
                                256,
                                ArrayConverter
                                        .hexStringToByteArray("6dd24d6dcce4b6ad0231bee56cf767fc06f05a03d5921093e70e79c0d885a2736dd646bdfdded6e3c1e5c6abcb7157418e8389085f83f68c3cf746004a55fa008ec8446200bf5031678abfd900841f6be1e68ed76335f59e1611244900f7c5ae3151f42739c28546be76c4ce476218b11e7b41cad7512fafe2c477e271878b83fd071b34e12f3f5ef5f36cf797d584fe104392f9444c4edbcc3f500bdf7c8ee7ce8aba60f2a857ab4668c9096a56c393e17cd04f0830a064827c16df35612720859802bf40f99879392231a38cf647464057cdfd98a13887d638503093688a5ab72dcb54f83922e685a694b6755df3ffabee778014b30883c284cb6af269b573"),
                                ProtocolVersion.TLS10 } });
    }

    private byte[] message;

    private HandshakeMessageType type;
    private int length;

    private int serializedKeyLength;
    private byte[] serializedKey;
    private ProtocolVersion version;

    public DHClientKeyExchangeParserTest(byte[] message, HandshakeMessageType type, int length,
            int serializedKeyLength, byte[] serializedKey, ProtocolVersion version) {
        this.message = message;
        this.type = type;
        this.length = length;
        this.serializedKeyLength = serializedKeyLength;
        this.serializedKey = serializedKey;
        this.version = version;
    }

    /**
     * Test of parse method, of class DHClientKeyExchangeParser.
     */
    @Test
    public void testParse() {
        DHClientKeyExchangeParser<DHClientKeyExchangeMessage> parser = new DHClientKeyExchangeParser(0, message,
                version);
        DHClientKeyExchangeMessage msg = parser.parse();
        assertArrayEquals(message, msg.getCompleteResultingMessage().getValue());
        assertTrue(msg.getLength().getValue() == length);
        assertTrue(msg.getType().getValue() == type.getValue());
        assertTrue(serializedKeyLength == msg.getPublicKeyLength().getValue());
        assertArrayEquals(serializedKey, msg.getPublicKey().getValue());
    }

}
