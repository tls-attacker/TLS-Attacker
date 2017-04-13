/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.constants.AlertDescription;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.util.LogLevel;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.ProbeResult;
import de.rub.nds.tlsscanner.flaw.ConfigurationFlaw;
import de.rub.nds.tlsscanner.flaw.FlawLevel;
import de.rub.nds.tlsscanner.report.ResultValue;
import de.rub.nds.tlsscanner.report.check.CheckType;
import de.rub.nds.tlsscanner.report.check.TLSCheck;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CiphersuiteProbe extends TLSProbe {

    private final List<ProtocolVersion> protocolVersions;

    public CiphersuiteProbe(ScannerConfig config) {
        super("Ciphersuite", config);
        protocolVersions = new LinkedList<>();
        protocolVersions.add(ProtocolVersion.TLS10);
        protocolVersions.add(ProtocolVersion.TLS11);
        protocolVersions.add(ProtocolVersion.TLS12);
    }

    @Override
    public ProbeResult call() {
        LOGGER.debug("Starting CiphersuiteProbe");
        Set<CipherSuite> supportedCiphersuites = new HashSet<>();
        Set<CipherSuite> tls10Ciphersuites = new HashSet<>();
        for (ProtocolVersion version : protocolVersions) {
            LOGGER.debug("Testing:" + version.name());
            List<CipherSuite> toTestList = new LinkedList<>();
            toTestList.addAll(Arrays.asList(CipherSuite.values()));
            toTestList.remove(CipherSuite.TLS_FALLBACK_SCSV);
            List<CipherSuite> versionSupportedSuites = getSupportedCipherSuitesFromList(toTestList, version);
            supportedCiphersuites.addAll(versionSupportedSuites);
            if (version == ProtocolVersion.TLS10) {
                tls10Ciphersuites.addAll(versionSupportedSuites);
            }
        }
        List<ResultValue> resultList = new LinkedList<>();
        List<TLSCheck> checkList = new LinkedList<>();
        for (CipherSuite suite : supportedCiphersuites) {
            resultList.add(new ResultValue("Ciphersuite", suite.name()));
        }
        checkList.add(checkAnonCiphers(supportedCiphersuites));
        checkList.add(checkCBCCiphers(tls10Ciphersuites));
        checkList.add(checkExportCiphers(supportedCiphersuites));
        checkList.add(checkNullCiphers(supportedCiphersuites));
        checkList.add(checkRC4Ciphers(supportedCiphersuites));

        return new ProbeResult(getProbeName(), resultList, checkList);

    }

    private boolean supportsExportCiphers(Set<CipherSuite> supportedCiphersuites) {
        for (CipherSuite suite : supportedCiphersuites) {
            if (suite.name().contains("EXPORT")) {
                return true;
            }
        }
        return false;
    }

    private boolean supportsRC4Ciphers(Set<CipherSuite> supportedCiphersuites) {
        for (CipherSuite suite : supportedCiphersuites) {
            if (suite.name().contains("RC4")) {
                return true;
            }
        }
        return false;
    }

    private boolean supportsAnonCiphers(Set<CipherSuite> supportedCiphersuites) {
        for (CipherSuite suite : supportedCiphersuites) {
            if (suite.name().contains("anon")) {
                return true;
            }
        }
        return false;
    }

    private boolean supportsCBCCiphers(Set<CipherSuite> supportedCiphersuites) {
        for (CipherSuite suite : supportedCiphersuites) {
            if (suite.name().contains("CBC")) {
                return true;
            }
        }
        return false;
    }

    private boolean supportsNullCiphers(Set<CipherSuite> supportedCiphersuites) {
        for (CipherSuite suite : supportedCiphersuites) {
            if (suite.name().contains("NULL")) {
                return true;
            }
        }
        return false;
    }

    public TLSCheck checkAnonCiphers(Set<CipherSuite> supportedCiphersuites) {
        boolean result = supportsAnonCiphers(supportedCiphersuites);
        return new TLSCheck(result, CheckType.CIPHERSUITE_ANON, getConfig().getLanguage());
    }

    public TLSCheck checkNullCiphers(Set<CipherSuite> supportedCiphersuites) {
        boolean result = supportsNullCiphers(supportedCiphersuites);
        return new TLSCheck(result, CheckType.CIPHERSUITE_NULL, getConfig().getLanguage());
    }

    public TLSCheck checkCBCCiphers(Set<CipherSuite> supportedCiphersuites) {
        boolean result = supportsCBCCiphers(supportedCiphersuites);
        return new TLSCheck(result, CheckType.CIPHERSUITE_CBC, getConfig().getLanguage());
    }

    public TLSCheck checkRC4Ciphers(Set<CipherSuite> supportedCiphersuites) {
        boolean result = supportsRC4Ciphers(supportedCiphersuites);
        return new TLSCheck(result, CheckType.CIPHERSUITE_RC4, getConfig().getLanguage());
    }

    public TLSCheck checkExportCiphers(Set<CipherSuite> supportedCiphersuites) {
        boolean result = supportsExportCiphers(supportedCiphersuites);
        return new TLSCheck(result, CheckType.CIPHERSUITE_EXPORT, getConfig().getLanguage());
    }

    public List<CipherSuite> getSupportedCipherSuitesFromList(List<CipherSuite> toTestList, ProtocolVersion version) {
        List<CipherSuite> listWeSupport = new LinkedList<>(toTestList);
        List<CipherSuite> supported = new LinkedList<>();

        boolean supportsMore = false;
        do {
            TlsConfig config = getConfig().createConfig();
            config.setSupportedCiphersuites(listWeSupport);
            config.setHighestProtocolVersion(version);
            config.setEnforceSettings(true);
            config.setAddServerNameIndicationExtension(false);
            config.setAddECPointFormatExtension(true);
            config.setAddEllipticCurveExtension(true);
            config.setAddSignatureAndHashAlgrorithmsExtension(true);
            List<NamedCurve> namedCurves = new LinkedList<>();
            namedCurves.addAll(Arrays.asList(NamedCurve.values()));
            config.setNamedCurves(namedCurves);
            WorkflowTrace trace = new WorkflowTrace();
            ClientHelloMessage message = new ClientHelloMessage(config);
            trace.add(new SendAction(message));
            trace.add(new ReceiveAction(new ServerHelloMessage()));
            config.setWorkflowTrace(trace);
            TlsContext tlsContext = new TlsContext(config);
            WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                    config.getExecutorType(), tlsContext);
            try {
                workflowExecutor.executeWorkflow();
            } catch (WorkflowExecutionException ex) {
                LOGGER.warn("Encountered exception while executing WorkflowTrace!");
                LOGGER.debug(ex);
                supportsMore = false;
            }
            if (!trace.getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.SERVER_HELLO).isEmpty()) {
                if (tlsContext.getSelectedProtocolVersion() != version) {
                    LOGGER.debug("Server does not support " + version);
                    return new LinkedList<>();
                }
                LOGGER.debug("Server chose " + tlsContext.getSelectedCipherSuite().name());
                supportsMore = true;
                supported.add(tlsContext.getSelectedCipherSuite());
                listWeSupport.remove(tlsContext.getSelectedCipherSuite());
            } else {
                supportsMore = false;
                LOGGER.debug("Server did not send ServerHello");
                LOGGER.debug(tlsContext.getWorkflowTrace().toString());
                if (tlsContext.isReceivedFatalAlert()) {
                    LOGGER.debug("Received Fatal Alert");
                    AlertMessage alert = (AlertMessage) tlsContext.getWorkflowTrace()
                            .getActualReceivedProtocolMessagesOfType(ProtocolMessageType.ALERT).get(0);
                    LOGGER.debug("Type:" + alert.toString());

                }
            }
        } while (supportsMore);
        return supported;
    }

}
