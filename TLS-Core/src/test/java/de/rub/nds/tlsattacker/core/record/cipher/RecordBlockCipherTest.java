/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class RecordBlockCipherTest {

    private TlsContext context;

    public RecordBlockCipherTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        Security.addProvider(new BouncyCastleProvider());
        UnlimitedStrengthEnabler.enable();
    }

    @Test
    public void testConstructors() {
        // This test just checks that the init() method will not break
        context.setClientRandom(new byte[] { 0 });
        context.setServerRandom(new byte[] { 0 });
        context.setMasterSecret(new byte[] { 0 });
        for (CipherSuite suite : CipherSuite.values()) {
            // TODO add fortezza and gost
            if (!suite.equals(CipherSuite.TLS_UNKNOWN_CIPHER) && !suite.isSCSV()
                    && AlgorithmResolver.getCipherType(suite) == CipherType.BLOCK && !suite.name().contains("FORTEZZA")
                    && !suite.name().contains("GOST") && !suite.name().contains("ARIA")) {
                context.setSelectedCipherSuite(suite);
                for (ConnectionEnd end : ConnectionEnd.values()) {
                    context.getConfig().setConnectionEnd(end);
                    for (ProtocolVersion version : ProtocolVersion.values()) {
                        if (version == ProtocolVersion.SSL2 || version == ProtocolVersion.SSL3) {
                            continue;
                        }
                        context.setSelectedProtocolVersion(version);
                        RecordBlockCipher cipher = new RecordBlockCipher(context);
                    }
                }
            }
        }
    }

    @Test
    public void test() {
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        context.setClientRandom(new byte[] { 0 });
        context.setServerRandom(new byte[] { 0 });
        context.setMasterSecret(new byte[] { 0 });
        context.getConfig().setConnectionEnd(ConnectionEnd.CLIENT);
        RecordBlockCipher cipher = new RecordBlockCipher(context);
    }

    /**
     * Test of calculateMac method, of class RecordBlockCipher.
     */
    @Test
    public void testCalculateMac() {
    }

    /**
     * Test of encrypt method, of class RecordBlockCipher.
     */
    @Test
    public void testEncrypt() {
    }

    /**
     * Test of decrypt method, of class RecordBlockCipher.
     */
    @Test
    public void testDecrypt() {
    }

    /**
     * Test of getMacLength method, of class RecordBlockCipher.
     */
    @Test
    public void testGetMacLength() {
    }

    /**
     * Test of calculatePadding method, of class RecordBlockCipher.
     */
    @Test
    public void testCalculatePadding() {
    }

    /**
     * Test of getPaddingLength method, of class RecordBlockCipher.
     */
    @Test
    public void testGetPaddingLength() {
    }

}
