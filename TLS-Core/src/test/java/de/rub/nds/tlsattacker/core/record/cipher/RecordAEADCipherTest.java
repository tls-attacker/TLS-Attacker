/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.socket.TlsAttackerSocket;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.transport.ClientConnectionEnd;
import de.rub.nds.tlsattacker.transport.ServerConnectionEnd;
import java.io.IOException;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.logging.log4j.core.config.Configurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.fail;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class RecordAEADCipherTest {

    private TlsContext context;
    private RecordAEADCipher cipher;

    public RecordAEADCipherTest() {
    }

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        this.context = new TlsContext();
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        context.setClientHandshakeTrafficSecret(ArrayConverter
                .hexStringToByteArray("4B63051EABCD514D7CB6D1899F472B9F56856B01BDBC5B733FBB47269E7EBDC2"));
        context.setServerHandshakeTrafficSecret(ArrayConverter
                .hexStringToByteArray("ACC9DB33EE0968FAE7E06DAA34D642B146092CE7F9C9CF47670C66A0A6CE1C8C"));
    }

    /**
     * Test of the encrypt method, of class RecordAEADCipher.
     */
    @Test
    public void testEncrypt() {
        context.setConnectionEnd(new ServerConnectionEnd());
        this.cipher = new RecordAEADCipher(context);
        byte[] plaintext = ArrayConverter.hexStringToByteArray("08000002000016");
        byte[] ciphertext = cipher.encrypt(plaintext);
        byte[] ciphertext_correct = ArrayConverter
                .hexStringToByteArray("1BB3293A919E0D66F145AE830488E8D89BE5EC16688229");
        assertArrayEquals(ciphertext, ciphertext_correct);
    }

    /**
     * Test of the decrypt method, of class RecordAEADCipher.
     */
    @Test
    public void testDecrypt() {
        context.setConnectionEnd(new ClientConnectionEnd());
        this.cipher = new RecordAEADCipher(context);
        byte[] ciphertext = ArrayConverter.hexStringToByteArray("1BB3293A919E0D66F145AE830488E8D89BE5EC16688229");
        byte[] plaintext = cipher.decrypt(ciphertext);
        byte[] plaintext_correct = ArrayConverter.hexStringToByteArray("08000002000016");
        assertArrayEquals(plaintext, plaintext_correct);
    }
}
