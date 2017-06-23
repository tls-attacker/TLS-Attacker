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
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 * @author Robert Merget - robert.merget@rub.de
 */
public class FinishedMessagePreparator extends HandshakeMessagePreparator<FinishedMessage> {

    private byte[] verifyData;
    private final FinishedMessage msg;

    public FinishedMessagePreparator(TlsContext context, FinishedMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing FinishedMessage");
        verifyData = computeVerifyData();

        prepareVerifyData(msg);
    }

    private byte[] computeVerifyData() {
        if (context.getSelectedProtocolVersion() == ProtocolVersion.TLS13) {
            try {
                String algorithm = AlgorithmResolver.getHKDFAlgorithm(context.getSelectedCipherSuite()).getMacAlgorithm().getJavaName();
                Mac mac = Mac.getInstance(algorithm);
                byte[] finishedKey;
                LOGGER.debug("Connection End: " + context.getConfig().getConnectionEnd());
                if (context.getConfig().getConnectionEnd() == ConnectionEnd.SERVER) {
                    finishedKey = HKDFunction.expandLabel(algorithm, context.getServerHandshakeTrafficSecret(),
                            HKDFunction.FINISHED, new byte[0], mac.getMacLength());
                } else {
                    finishedKey = HKDFunction.expandLabel(algorithm, context.getClientHandshakeTrafficSecret(),
                            HKDFunction.FINISHED, new byte[0], mac.getMacLength());
                }
                LOGGER.debug("Finisched key: " + ArrayConverter.bytesToHexString(finishedKey));
                SecretKeySpec keySpec = new SecretKeySpec(finishedKey, algorithm);
                mac.init(keySpec);
                mac.update(context.getDigest().digest(context.getSelectedProtocolVersion(), context.getSelectedCipherSuite()));
                return mac.doFinal();
            } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
                throw new CryptoException(ex);
            }
        } else {
            PRFAlgorithm prfAlgorithm = context.getPRFAlgorithm();
            byte[] masterSecret = context.getMasterSecret();
            byte[] handshakeMessageHash = context.getDigest().digest(context.getSelectedProtocolVersion(),
                    context.getSelectedCipherSuite());

            if (context.getConfig().getConnectionEnd() == ConnectionEnd.SERVER) {
                // TODO put this in seperate config option
            return PseudoRandomFunction.compute(prfAlgorithm, masterSecret, PseudoRandomFunction.SERVER_FINISHED_LABEL,
                    handshakeMessageHash, HandshakeByteLength.VERIFY_DATA);
            } else {
            return PseudoRandomFunction.compute(prfAlgorithm, masterSecret, PseudoRandomFunction.CLIENT_FINISHED_LABEL,
                    handshakeMessageHash, HandshakeByteLength.VERIFY_DATA);
            }
        }
    }

    private void prepareVerifyData(FinishedMessage msg) {
        msg.setVerifyData(verifyData);
        LOGGER.debug("VerifyData: " + ArrayConverter.bytesToHexString(msg.getVerifyData().getValue()));
    }

}
