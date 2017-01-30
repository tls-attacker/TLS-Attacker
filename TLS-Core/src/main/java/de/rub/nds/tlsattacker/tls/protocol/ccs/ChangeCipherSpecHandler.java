/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.ccs;

import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.crypto.TlsRecordBlockCipher;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class ChangeCipherSpecHandler extends ProtocolMessageHandler<ChangeCipherSpecMessage> {

    public static final byte CCS_PROTOCOL_TYPE = 1;

    public ChangeCipherSpecHandler(TlsContext tlsContext) {
        super(tlsContext);
        correctProtocolMessageClass = ChangeCipherSpecMessage.class;
    }

    @Override
    public byte[] prepareMessageAction() {
        protocolMessage.setCcsProtocolType(CCS_PROTOCOL_TYPE);
        if ((tlsContext.getConfig().isRenegotiation() && tlsContext.getConfig().getMyConnectionEnd() == ConnectionEnd.CLIENT)
                || tlsContext.getRecordHandler().getRecordCipher() == null) {
            setRecordCipher();
        }
        tlsContext.getRecordHandler().setEncryptSending(true);
        byte[] result = { protocolMessage.getCcsProtocolType().getValue() };
        return result;
    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
        if ((tlsContext.getConfig().isRenegotiation() && tlsContext.getConfig().getMyConnectionEnd() == ConnectionEnd.SERVER)
                || tlsContext.getRecordHandler().getRecordCipher() == null) {
            setRecordCipher();
        }
        protocolMessage.setCcsProtocolType(message[pointer]);
        tlsContext.getRecordHandler().setDecryptReceiving(true);
        return pointer + 1;
    }

    public void setRecordCipher() {
        TlsRecordBlockCipher tlsRecordBlockCipher = null;
        do {
            try {
                tlsRecordBlockCipher = new TlsRecordBlockCipher(tlsContext);
                tlsContext.getRecordHandler().setRecordCipher(tlsRecordBlockCipher);
            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
                    | InvalidAlgorithmParameterException ex) {
                if (tlsContext.getConfig().isFuzzingMode()) {
                    throw new UnsupportedOperationException(
                            "It was not possible to initialize an algorithm from "
                                    + tlsContext.getSelectedCipherSuite()
                                    + ". Most probably your platform does not support unlimited policy strength and you have to "
                                    + "install Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files. Stupid, I know.",
                            ex);
                } else {
                    LOGGER.debug("Changed Ciphersuite on the fly");
                    tlsContext.setSelectedCipherSuite(CipherSuite.getRandom());
                }
            }
        } while (tlsRecordBlockCipher == null);
    }
}
