/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer.rule;

import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.File;
import java.io.IOException;
import java.util.List;
import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBException;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.config.analyzer.ProtocolVersionRuleConfig;
import tlsattacker.fuzzer.result.AgentResult;
import tlsattacker.fuzzer.testvector.TestVectorSerializer;

/**
 * This Rule checks, if the Client and the Server negotiated the highest
 * Protocol Version both supported. And if the ProtocolVersion Field received
 * from the Implementation is reasonable. One can specify Blacklisted
 * ProtocolVersions which should not be negotiated by the Server
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ProtocolVersionRule extends Rule {

    /**
     * The number of TestVectors that this rule applied to
     */
    private int found = 0;

    /**
     * The highest supported TLS Protocolversion of the tested implementation
     */
    private final ProtocolVersion highestTLSSupported;

    /**
     * The highest supported DTLS Protocolverison of the tested implementation
     */
    private final ProtocolVersion highestDTLSSupported;

    /**
     * The configuration object for this rule
     */
    private ProtocolVersionRuleConfig config;

    public ProtocolVersionRule(EvolutionaryFuzzerConfig evoConfig) {
        super(evoConfig, "highest_version.rule");
        File f = new File(evoConfig.getAnalyzerConfigFolder() + configFileName);
        if (f.exists()) {
            config = JAXB.unmarshal(f, ProtocolVersionRuleConfig.class);
        }
        if (config == null) {
            config = new ProtocolVersionRuleConfig();
            writeConfig(config);
        }
        prepareConfigOutputFolder();
        // TODO Dynamic Discover Highest supported
        highestTLSSupported = ProtocolVersion.TLS12;
        highestDTLSSupported = ProtocolVersion.DTLS12;
    }

    /**
     * The rule applies if the Server did not choose the highest offered version
     * it supports
     * 
     * @param result
     *            AgentResult to analyze
     * @return True if the Server did not choos the highest offered version it
     *         supports
     */
    @Override
    public boolean applies(AgentResult result) {
        ProtocolVersion serverVersion = null;

        WorkflowTrace trace = result.getVector().getTrace();
        List<HandshakeMessage> sentClientHellos = trace
                .getActuallySentHandshakeMessagesOfType(HandshakeMessageType.CLIENT_HELLO);
        List<HandshakeMessage> receivedServerHellos = trace
                .getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.SERVER_HELLO);
        if (sentClientHellos.isEmpty() || receivedServerHellos.isEmpty()) {
            return false;
        }
        ClientHelloMessage clientMessage = (ClientHelloMessage) sentClientHellos.get(0);
        ServerHelloMessage serverMessage = (ServerHelloMessage) receivedServerHellos.get(0);

        byte[] clientProtocolVersions = clientMessage.getProtocolVersion().getValue();
        byte[] serverProtocolVersions = serverMessage.getProtocolVersion().getValue();

        if (serverProtocolVersions.length != 2) {
            // The Server returned an invalid protocolversion size field
            return true;
        } else {
            serverVersion = ProtocolVersion.getProtocolVersion(serverProtocolVersions);
            if (serverVersion == null) {
                // ServerVersion is nonstandart, always report
                return true;
            } else if (!config.isAllowedVersion(serverVersion)) {
                // ServerVersion is on Blacklist
                return true;
            }
        }

        int intRepresentationClientVersion = clientProtocolVersions[0] * 0x100 + clientProtocolVersions[1];
        int intRepresentationServerVersion = serverProtocolVersions[0] * 0x100 + serverProtocolVersions[1];
        if (clientProtocolVersions[0] == (byte) 0xFE && serverProtocolVersions[0] == (byte) 0xFE) {
            // We are some DTLS Protocolversion
            // We chose dtls and the server agreed on some DTLS Version
            return intRepresentationClientVersion < intRepresentationServerVersion
                    && serverVersion != highestDTLSSupported;

        } else if ((clientProtocolVersions[0] == (byte) 0xFE && serverProtocolVersions[0] != (byte) 0xFE)
                || (clientProtocolVersions[0] != (byte) 0xFE && serverProtocolVersions[0] == (byte) 0xFE)) {
            // DTLS TLS mismatch
            return true;
        } else {
            return intRepresentationClientVersion > intRepresentationServerVersion
                    && serverVersion != highestTLSSupported;
        }
    }

    /**
     * Stores the Testvector and adds a description to the TestVector that
     * described the violation
     * 
     * @param result
     *            AgentResult to analyze
     */
    @Override
    public synchronized void onApply(AgentResult result) {
        WorkflowTrace trace = result.getVector().getTrace();
        List<HandshakeMessage> sentClientHellos = trace
                .getActuallySentHandshakeMessagesOfType(HandshakeMessageType.CLIENT_HELLO);
        List<HandshakeMessage> receivedServerHellos = trace
                .getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.SERVER_HELLO);
        ClientHelloMessage clientMessage = (ClientHelloMessage) sentClientHellos.get(0);
        ServerHelloMessage serverMessage = (ServerHelloMessage) receivedServerHellos.get(0);

        byte[] clientProtocolVersions = clientMessage.getProtocolVersion().getValue();
        byte[] serverProtocolVersions = serverMessage.getProtocolVersion().getValue();

        found++;
        File f = new File(evoConfig.getOutputFolder() + config.getOutputFolder() + result.getId());
        try {
            result.getVector()
                    .getTrace()
                    .setDescription(
                            "WorkflowTrace contains unusual Protocolversions: Client("
                                    + ArrayConverter.bytesToHexString(clientProtocolVersions) + ") Server("
                                    + ArrayConverter.bytesToHexString(serverProtocolVersions) + ")");
            TestVectorSerializer.write(f, result.getVector());
        } catch (JAXBException | IOException ex) {
            LOGGER.error(
                    "Could not write Results to Disk! Does the Fuzzer have the rights to write to "
                            + f.getAbsolutePath(), ex);
        }

    }

    /**
     * Do nothing
     * 
     * @param result
     *            AgentResult to analyze
     */
    @Override
    public void onDecline(AgentResult result) {
    }

    /**
     * Generates a status report
     * 
     * @return
     */
    @Override
    public synchronized String report() {

        if (found > 0) {
            return "Found " + found + " Traces which had unusual Protocolversions\n";
        } else {
            return null;
        }
    }

    @Override
    public ProtocolVersionRuleConfig getConfig() {
        return config;
    }

}
