/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.impl.RecordLayer;
import de.rub.nds.tlsattacker.core.record.cipher.CipherState;
import de.rub.nds.tlsattacker.core.record.cipher.RecordBlockCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordNullCipher;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.JAXBException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class ResetConnectionActionTest extends AbstractActionTest<ResetConnectionAction> {

    private final TlsContext context;

    ResetConnectionActionTest() throws NoSuchAlgorithmException, CryptoException {
        super(new ResetConnectionAction(), ResetConnectionAction.class);
        context = state.getTlsContext();
        context.setTransportHandler(new FakeTransportHandler(ConnectionEndType.CLIENT));
        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        RecordCipher recordCipher =
                new RecordBlockCipher(
                        context,
                        new CipherState(
                                context.getChooser().getSelectedProtocolVersion(),
                                context.getChooser().getSelectedCipherSuite(),
                                KeySetGenerator.generateKeySet(context),
                                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        context.getRecordLayer().updateEncryptionCipher(recordCipher);
        context.getRecordLayer().updateDecryptionCipher(recordCipher);
        context.setActiveClientKeySetType(Tls13KeySetType.EARLY_TRAFFIC_SECRETS);
        context.setActiveServerKeySetType(Tls13KeySetType.EARLY_TRAFFIC_SECRETS);
    }

    @Test
    public void testExecute() throws Exception {
        super.testExecute();
        RecordLayer layer = (RecordLayer) context.getRecordLayer();
        assertTrue(layer.getEncryptorCipher() instanceof RecordNullCipher);
        assertTrue(layer.getDecryptorCipher() instanceof RecordNullCipher);
        assertTrue(layer.getEncryptorCipher() instanceof RecordNullCipher);
        assertTrue(layer.getDecryptorCipher() instanceof RecordNullCipher);
        assertEquals(context.getActiveClientKeySetType(), Tls13KeySetType.NONE);
        assertEquals(context.getActiveServerKeySetType(), Tls13KeySetType.NONE);
        assertFalse(context.getTransportHandler().isClosed());
    }

    @Test
    @Disabled("To be fixed")
    @Override
    public void testMarshalingEmptyActionYieldsMinimalOutput() throws JAXBException, IOException {
        super.testMarshalingEmptyActionYieldsMinimalOutput();
    }
}
