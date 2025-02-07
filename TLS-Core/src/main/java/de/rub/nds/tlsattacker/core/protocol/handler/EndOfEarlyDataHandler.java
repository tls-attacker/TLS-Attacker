/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.EndOfEarlyDataMessage;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EndOfEarlyDataHandler extends HandshakeMessageHandler<EndOfEarlyDataMessage> {

    @SuppressWarnings("unused")
    private static final Logger LOGGER = LogManager.getLogger();

    public EndOfEarlyDataHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(EndOfEarlyDataMessage message) {
        // nothing to adjust
    }

    @Override
    public void adjustContextAfterSerialize(EndOfEarlyDataMessage message) {
        if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
            setClientRecordCipher();
            setServertRecordCipher();
        }
    }

    private void setClientRecordCipher() {
        tlsContext.setActiveClientKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
        KeySet keySet = tlsContext.getkeySetHandshake();

        if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.SERVER) {
            tlsContext
                    .getRecordLayer()
                    .updateDecryptionCipher(
                            RecordCipherFactory.getRecordCipher(tlsContext, keySet, false));
        } else {
            tlsContext
                    .getRecordLayer()
                    .updateEncryptionCipher(
                            RecordCipherFactory.getRecordCipher(tlsContext, keySet, true));
        }
    }

    private void setServertRecordCipher() {
        tlsContext.setActiveClientKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
        KeySet keySet = tlsContext.getkeySetHandshake();

        if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.SERVER) {
            tlsContext
                    .getRecordLayer()
                    .updateDecryptionCipher(
                            RecordCipherFactory.getRecordCipher(tlsContext, keySet, true));
        } else {
            tlsContext
                    .getRecordLayer()
                    .updateEncryptionCipher(
                            RecordCipherFactory.getRecordCipher(tlsContext, keySet, false));
        }
    }
}
