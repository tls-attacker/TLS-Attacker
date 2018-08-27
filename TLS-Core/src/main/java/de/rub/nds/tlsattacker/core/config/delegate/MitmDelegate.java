/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The MitmDelegate parses an arbitrary number of {Client,Server}ConnectionEnds
 * from command line. It requires at least one "accepting" and one "connecting"
 * connection end.
 */
public class MitmDelegate extends Delegate {

    private static final Logger LOGGER = LogManager.getLogger();

    @Parameter(names = "-accept", description = "A MiTM client can connect to this connection end."
            + " Allowed syntax: <PORT> or <CONNECTION_ALIAS>:<PORT>")
    protected String inboundConnectionStr;

    @Parameter(names = "-connect", description = "Add a server to which the MiTM will connect to."
            + " Allowed syntax: <HOSTNAME>:<PORT> or <CONNECTION_ALIAS>:<HOSTNAME>:<PORT>")
    protected String outboundConnectionStr;

    public MitmDelegate() {
    }

    public String getInboundConnectionStr() {
        return inboundConnectionStr;
    }

    public void setInboundConnectionStr(String inboundConnectionStr) {
        this.inboundConnectionStr = inboundConnectionStr;
    }

    public String getOutboundConnectionStr() {
        return outboundConnectionStr;
    }

    public void setOutboundConnectionStr(String outboundConnectionStr) {
        this.outboundConnectionStr = outboundConnectionStr;
    }

    @Override
    public void applyDelegate(Config config) {

        config.setDefaulRunningMode(RunningModeType.MITM);

        if (inboundConnectionStr != null) {
            setInboundConnection(config);
        } else {
            LOGGER.debug("Parameter -accept not specified. Using inbound connection from "
                    + "-workflow_input or config defaults.");
        }

        if (outboundConnectionStr != null) {
            setOutboundConnection(config);
        } else {
            LOGGER.debug("Parameter -connect not specified. Using outbound connection from "
                    + "-workflow_input or config defaults.");
        }

    }

    private void setInboundConnection(Config config) {
        InboundConnection inboundConnection = config.getDefaultServerConnection();
        if (inboundConnection == null) {
            inboundConnection = new InboundConnection();
            config.setDefaultServerConnection(inboundConnection);
        }
        String[] parsedPort = inboundConnectionStr.split(":");
        switch (parsedPort.length) {
            case 1:
                inboundConnection.setAlias("accept:" + parsedPort[0]);
                inboundConnection.setPort(parsePort(parsedPort[0]));
                break;
            case 2:
                inboundConnection.setAlias(parsedPort[0]);
                inboundConnection.setPort(parsePort(parsedPort[1]));
                break;
            default:
                throw new ConfigurationException("Could not parse provided accepting connection" + " end: "
                        + inboundConnectionStr + ". Expected [CONNECTION_ALIAS:]<PORT>");
        }
        config.setDefaultServerConnection(inboundConnection);
    }

    private void setOutboundConnection(Config config) {
        OutboundConnection outboundConnection = config.getDefaultClientConnection();
        if (outboundConnection == null) {
            outboundConnection = new OutboundConnection();
            config.setDefaultClientConnection(outboundConnection);
        }
        String[] parsedHost = outboundConnectionStr.split(":");
        switch (parsedHost.length) {
            case 2:
                outboundConnection.setHostname(parsedHost[0]);
                outboundConnection.setPort(parsePort(parsedHost[1]));
                outboundConnection.setAlias(outboundConnectionStr);
                break;
            case 3:
                outboundConnection.setAlias(parsedHost[0]);
                outboundConnection.setHostname(parsedHost[1]);
                outboundConnection.setPort(parsePort(parsedHost[2]));
                break;
            default:
                throw new ConfigurationException("Could not parse provided server address: " + outboundConnectionStr
                        + ". Expected [CONNECTION_ALIAS:]<HOSTNAME>:<PORT>");
        }
        config.setDefaultClientConnection(outboundConnection);
    }

    private int parsePort(String portStr) {
        int port = Integer.parseInt(portStr);
        if (port < 0 || port > 65535) {
            throw new ParameterException("port must be in interval [0,65535], but is " + port);
        }
        return port;
    }
}
