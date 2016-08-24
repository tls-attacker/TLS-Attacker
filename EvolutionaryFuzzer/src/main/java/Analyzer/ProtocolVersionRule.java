/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Analyzer;

import Config.Analyzer.IsTimeoutRuleConfig;
import Config.Analyzer.ProtocolVersionRuleConfig;
import Config.EvolutionaryFuzzerConfig;
import Result.Result;
import TestVector.TestVectorSerializer;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.File;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBException;

/**
 * This Rule checks, if the Client and the Server negotiated the highest
 * Protocol Version both supported. And if the ProtocolVersion Field received
 * from the Implementation is reasonable. One can specify Blacklisted
 * ProtocolVersions which should not be negotiated by the Server
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ProtocolVersionRule extends Rule {

    private int found = 0;
    private final ProtocolVersion highestTLSSupported;
    private final ProtocolVersion highestDTLSSupported;
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

    @Override
    public boolean applys(Result result) {
	ProtocolVersion clientVersion = null;
	ProtocolVersion serverVersion = null;

	WorkflowTrace trace = result.getExecutedVector().getTrace();
	ClientHelloMessage clientMessage = (ClientHelloMessage) trace
		.getFirstHandshakeMessage(HandshakeMessageType.CLIENT_HELLO);
	ServerHelloMessage serverMessage = (ServerHelloMessage) trace
		.getFirstHandshakeMessage(HandshakeMessageType.SERVER_HELLO);

	if (clientMessage == null || serverMessage == null) {
	    return false;
	}
	byte[] clientProtocolVersions = clientMessage.getProtocolVersion().getValue();
	byte[] serverProtocolVersions = serverMessage.getProtocolVersion().getValue();

	if (clientProtocolVersions.length != 2 && config.isLogOnWrongFieldSizes()) {
	    // Our protocol Version is too short/long but server responded
	    // anyways
	    return true;
	} else {
	    clientVersion = ProtocolVersion.getProtocolVersion(clientProtocolVersions);
	}
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

    @Override
    public void onApply(Result result) {
	WorkflowTrace trace = result.getExecutedVector().getTrace();
	ClientHelloMessage clientMessage = (ClientHelloMessage) trace
		.getFirstHandshakeMessage(HandshakeMessageType.CLIENT_HELLO);
	ServerHelloMessage serverMessage = (ServerHelloMessage) trace
		.getFirstHandshakeMessage(HandshakeMessageType.SERVER_HELLO);
	byte[] clientProtocolVersions = clientMessage.getProtocolVersion().getValue();
	byte[] serverProtocolVersions = serverMessage.getProtocolVersion().getValue();

	found++;
	File f = new File(evoConfig.getOutputFolder() + config.getOutputFolder() + result.getId());
	try {
	    result.getExecutedVector()
		    .getTrace()
		    .setDescription(
			    "WorkflowTrace contains unusual Protocolversions: Client("
				    + ArrayConverter.bytesToHexString(clientProtocolVersions) + ") Server("
				    + ArrayConverter.bytesToHexString(serverProtocolVersions) + ")");
	    TestVectorSerializer.write(f, result.getExecutedVector());
	} catch (JAXBException | IOException E) {
	    LOG.log(Level.SEVERE,
		    "Could not write Results to Disk! Does the Fuzzer have the rights to write to "
			    + f.getAbsolutePath(), E);
	}

    }

    @Override
    public void onDecline(Result result) {
    }

    @Override
    public String report() {

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

    private static final Logger LOG = Logger.getLogger(ProtocolVersionRule.class.getName());

}
