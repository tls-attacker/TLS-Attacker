/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.util.FixedTimeProvider;
import de.rub.nds.tlsattacker.util.TimeHelper;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class ServerHelloPreparatorTest {

    private static final Logger LOGGER = LogManager.getLogger();

    private ServerHelloMessage message;
    private TlsContext context;
    private ServerHelloPreparator preparator;

    @Before
    public void setUp() {
        this.message = new ServerHelloMessage();
        this.context = new TlsContext();
        this.preparator = new ServerHelloPreparator(context.getChooser(), message);
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class
     * ServerHelloPreparator.
     */
    @Test
    public void testPrepare() {
        TimeHelper.setProvider(new FixedTimeProvider(12345l));
        List<CipherSuite> suiteList = new LinkedList<>();
        context.getConfig().setHighestProtocolVersion(ProtocolVersion.TLS12);
        suiteList.add(CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256);
        suiteList.add(CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        suiteList.add(CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256);
        context.setClientSupportedCiphersuites(suiteList);
        List<CipherSuite> ourSuiteList = new LinkedList<>();
        ourSuiteList.add(CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        List<CompressionMethod> ourCompressionList = new LinkedList<>();
        ourCompressionList.add(CompressionMethod.LZS);
        context.getConfig().setDefaultClientSupportedCiphersuites(ourSuiteList);
        context.getConfig().setDefaultServerSupportedCompressionMethods(ourCompressionList);
        context.setHighestClientProtocolVersion(ProtocolVersion.TLS11);
        List<CompressionMethod> compressionList = new LinkedList<>();
        compressionList.add(CompressionMethod.NULL);// same as CipherSuite
        compressionList.add(CompressionMethod.LZS);// same as CipherSuite
        context.setClientSupportedCompressions(compressionList);
        context.getConfig().setDefaultServerSessionId(new byte[] { 0, 1, 2, 3, 4, 5 });
        preparator.prepare();
        assertArrayEquals(ProtocolVersion.TLS11.getValue(), message.getProtocolVersion().getValue());
        assertArrayEquals(ArrayConverter.longToUint32Bytes(12345l), message.getUnixTime().getValue());
        LOGGER.info(ArrayConverter.bytesToHexString(message.getRandom().getValue()));
        assertArrayEquals(ArrayConverter.concatenate(ArrayConverter.longToUint32Bytes(12345l),
                ArrayConverter.hexStringToByteArray("60B420BB3851D9D47ACB933DBE70399BF6C92DA33AF01D4FB770E98C")),
                message.getRandom().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("000102030405"), message.getSessionId().getValue());
        assertTrue(6 == message.getSessionIdLength().getValue());
        assertTrue(message.getExtensionBytes().getValue().length == 0);
        assertTrue(0 == message.getExtensionsLength().getValue());
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }
}
