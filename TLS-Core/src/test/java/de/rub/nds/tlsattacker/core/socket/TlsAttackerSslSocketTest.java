/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.socket;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import java.io.IOException;
import java.security.Security;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;

public class TlsAttackerSslSocketTest {

    private static final Logger LOGGER = LogManager.getLogger();

    public TlsAttackerSslSocketTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getSupportedCipherSuites method, of class TlsAttackerSslSocket.
     */

    public void exampleUsage() {
        Security.addProvider(new BouncyCastleProvider());
        try {
            Config config = Config.createConfig();
            byte[] targetClientHello = ArrayConverter.hexStringToByteArray(
                "010001fc0303cb0186befd01343434eb32fc55d1d1cdc98ed9167c170d9d753bf7dd912bca5f20fbd2421948f45d8ace3529a61ae21529d3c16ac77aea49a79ca135247aa465f50020baba130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f003501000193dada000000000010000e00000b6578616d706c652e636f6d00170000ff01000100000a000a00085a5a001d00170018000b00020100002300000010000e000c02683208687474702f312e31000500050100000000000d0012001004030804040105030805050108060601001200000033002b00295a5a000100001d00202efd9e055aa93e599a61ed90d8f78fba72367db45e8fc93e1deecc32143afa3c002d00020101002b000b0afafa0304030303020301001b00030200029a9a000100001500d10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
            TlsAttackerSslSocket instance =
                new TlsAttackerSslSocket(config, "localhost", 4433, 1000, targetClientHello);
            instance.startHandshake();
            System.out.println("ok - fingers crossed this works");
            instance.getOutputStream().write("test".getBytes());
            instance.getOutputStream().flush();
            byte[] buffer = new byte[10];
            instance.getInputStream().read(buffer);
            System.out.println("Received: " + new String(buffer));
            instance.getOutputStream().write("Looks liek it".getBytes());
            instance.getOutputStream().flush();
        } catch (IOException ex) {
            LOGGER.error(ex);
        }

    }

}
