/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.util.FixedTimeProvider;
import de.rub.nds.tlsattacker.util.TimeHelper;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Test;

public class ServerHelloPreparatorTest
        extends AbstractProtocolMessagePreparatorTest<ServerHelloMessage, ServerHelloPreparator> {

    public ServerHelloPreparatorTest() {
        super(ServerHelloMessage::new, ServerHelloMessage::new, ServerHelloPreparator::new);
    }

    /** Test of prepareHandshakeMessageContents method, of class ServerHelloPreparator. */
    @Test
    @Override
    public void testPrepare() {
        TimeHelper.setProvider(new FixedTimeProvider(12345L));
        List<CipherSuite> suiteList = new LinkedList<>();
        context.getConfig().setHighestProtocolVersion(ProtocolVersion.TLS12);
        suiteList.add(CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256);
        suiteList.add(CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        suiteList.add(CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256);
        context.setClientSupportedCipherSuites(suiteList);
        List<CipherSuite> ourSuiteList = new LinkedList<>();
        ourSuiteList.add(CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        List<CompressionMethod> ourCompressionList = new LinkedList<>();
        ourCompressionList.add(CompressionMethod.LZS);
        context.getConfig().setDefaultClientSupportedCipherSuites(ourSuiteList);
        context.getConfig().setDefaultServerSupportedCompressionMethods(ourCompressionList);
        context.setHighestClientProtocolVersion(ProtocolVersion.TLS11);
        List<CompressionMethod> compressionList = new LinkedList<>();
        compressionList.add(CompressionMethod.NULL); // same as CipherSuite
        compressionList.add(CompressionMethod.LZS); // same as CipherSuite
        context.setClientSupportedCompressions(compressionList);
        context.getConfig().setDefaultServerSessionId(new byte[] {0, 1, 2, 3, 4, 5});
        preparator.prepare();
        assertArrayEquals(
                ProtocolVersion.TLS11.getValue(), message.getProtocolVersion().getValue());
        assertArrayEquals(
                ArrayConverter.longToUint32Bytes(12345L), message.getUnixTime().getValue());
        assertArrayEquals(
                ArrayConverter.concatenate(
                        ArrayConverter.longToUint32Bytes(12345L),
                        ArrayConverter.hexStringToByteArray(
                                "60B420BB3851D9D47ACB933DBE70399BF6C92DA33AF01D4FB770E98C")),
                message.getRandom().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("000102030405"),
                message.getSessionId().getValue());
        assertEquals(6, (int) message.getSessionIdLength().getValue());
        assertEquals(0, message.getExtensionBytes().getValue().length);
        assertEquals(0, (int) message.getExtensionsLength().getValue());
    }
}
