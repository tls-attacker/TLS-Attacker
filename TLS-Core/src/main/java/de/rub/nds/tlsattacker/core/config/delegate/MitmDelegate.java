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
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.transport.ClientConnectionEnd;
import de.rub.nds.tlsattacker.transport.ServerConnectionEnd;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;

/**
 * The MitmDelegate parses an arbitrary number of {Client,Server}ConnectionEnds
 * from command line. It requires at least one "accepting" and one "connecting"
 * connection end.
 *
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
public class MitmDelegate extends Delegate {

    private static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger("Config");

    @Parameter(names = "-accept", required = true, description = "A MiTM client can connect to this connection end."
            + " Allowed syntax: <PORT> or <CONNECTION_ALIAS>:<PORT>")
    protected List<String> acceptingConnectionEnds = new ArrayList<>();

    @Parameter(names = "-connect", required = true, description = "Add a server to which the MiTM will connect to."
            + " Allowed syntax: <HOSTNAME>:<PORT> or <CONNECTION_ALIAS>:<HOSTNAME>:<PORT>")
    protected List<String> connectingConnectionEnds = new ArrayList<>();

    public MitmDelegate() {
    }

    public List<String> getAcceptingConnectionEnds() {
        return acceptingConnectionEnds;
    }

    public void setAcceptingConnectionEnds(List<String> acceptingConnectionEnds) {
        this.acceptingConnectionEnds = acceptingConnectionEnds;
    }

    public List<String> getConnectingConnectionEnds() {
        return connectingConnectionEnds;
    }

    public void setConnectingConnectionEnds(List<String> connectingConnectionEnds) {
        this.connectingConnectionEnds = connectingConnectionEnds;
    }

    /**
     * Parse provided connections into ConnectionEnds before adding them to
     * config.
     * 
     * @param config
     */
    @Override
    public void applyDelegate(Config config) {

        if ((acceptingConnectionEnds == null) || (connectingConnectionEnds == null)) {
            // Though {accepting,connecting}ConnectionEnds are required
            // parameters we can get here if we call applyDelegate
            // manually, e.g. in tests.
            throw new ParameterException("{accepting|connecting}ConnectionEnds is empty!");
        }

        config.clearConnectionEnds();

        for (String conEndStr : acceptingConnectionEnds) {
            ServerConnectionEnd serverConEnd = new ServerConnectionEnd();

            String[] parsedPort = conEndStr.split(":");
            switch (parsedPort.length) {
                case 1:
                    serverConEnd.setAlias("accept:" + parsedPort[0]);
                    serverConEnd.setPort(parsePort(parsedPort[0]));
                    break;
                case 2:
                    serverConEnd.setAlias(parsedPort[0]);
                    serverConEnd.setPort(parsePort(parsedPort[1]));
                    break;
                default:
                    throw new ConfigurationException("Could not parse provided accepting connection" + " end: "
                            + conEndStr + ". Expected [CONNECTION_ALIAS:]<PORT>");
            }
            config.addConnectionEnd(serverConEnd);
        }

        for (String conEndStr : connectingConnectionEnds) {
            ClientConnectionEnd clientConEnd = new ClientConnectionEnd();

            String[] parsedHost = conEndStr.split(":");
            switch (parsedHost.length) {
                case 2:
                    clientConEnd.setHostname(parsedHost[0]);
                    clientConEnd.setPort(parsePort(parsedHost[1]));
                    clientConEnd.setAlias(conEndStr);
                    break;
                case 3:
                    clientConEnd.setAlias(parsedHost[0]);
                    clientConEnd.setHostname(parsedHost[1]);
                    clientConEnd.setPort(parsePort(parsedHost[2]));
                    break;
                default:
                    throw new ConfigurationException("Could not parse provided server address: " + conEndStr
                            + ". Expected [CONNECTION_ALIAS:]<HOSTNAME>:<PORT>");
            }
            config.addConnectionEnd(clientConEnd);
        }
    }

    private int parsePort(String portStr) {
        int port = Integer.parseInt(portStr);
        if (port < 0 || port > 65535) {
            throw new ParameterException("port must be in interval [0,65535], but is " + port);
        }
        return port;
    }

}
