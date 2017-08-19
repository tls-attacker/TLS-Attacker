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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.state.ConnectionEnd;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;

/**
 *
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
public class MitmDelegate extends Delegate {

    private static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger("Config");

    @Parameter(names = "-listen_port", required = true, description = "A MiTM client can connect to this port."
            + " Multiple ports can be added. At least one is required."
            + " Allowed syntax: <PORT> or <CONNECTION_ALIAS>:<PORT>")
    protected List<String> listenPorts = new ArrayList<>();

    @Parameter(names = "-connect", required = true, description = "Add a server to which the MiTM will connect to."
            + " Multiple destinations can be added. At least one is required."
            + " Allowed syntax: <HOSTNAME>:<PORT> or <CONNECTION_ALIAS>:<HOSTNAME>:<PORT>")
    protected List<String> serverHosts = new ArrayList<>();

    public MitmDelegate() {
    }

    public List<String> getListenPorts() {
        return listenPorts;
    }

    public void setListenPorts(List<String> listenPorts) {
        this.listenPorts = listenPorts;
    }

    public List<String> getServerHosts() {
        return serverHosts;
    }

    public void setServerHosts(List<String> serverHosts) {
        this.serverHosts = serverHosts;
    }

    /**
     * Parse provided connections into ConnectionEnds before adding them to
     * config.
     * 
     * @param config
     */
    @Override
    public void applyDelegate(Config config) {
        for (String port : listenPorts) {
            ConnectionEnd clientCon = new ConnectionEnd();
            clientCon.setConnectionEndType(ConnectionEndType.SERVER);

            String[] parsedPort = port.split(":");
            switch (parsedPort.length) {
                case 1:
                    clientCon.setAlias("client:" + parsedPort[0]);
                    clientCon.setPort(Integer.parseInt(parsedPort[0]));
                    break;
                case 2:
                    clientCon.setAlias(parsedPort[0]);
                    clientCon.setPort(Integer.parseInt(parsedPort[1]));
                    break;
                default:
                    throw new ConfigurationException("Could not parse provided listen port: " + port
                            + ". Expected [CONNECTION_ALIAS:]<PORT>");
            }
            config.addConnectionEnd(clientCon);
        }

        for (String host : serverHosts) {
            ConnectionEnd serverCon = new ConnectionEnd();
            serverCon.setConnectionEndType(ConnectionEndType.CLIENT);

            String[] parsedHost = host.split(":");
            switch (parsedHost.length) {
                case 2:
                    serverCon.setHostname(parsedHost[0]);
                    serverCon.setPort(Integer.parseInt(parsedHost[1]));
                    serverCon.setAlias(host);
                    break;
                case 3:
                    serverCon.setAlias(parsedHost[0]);
                    serverCon.setHostname(parsedHost[1]);
                    serverCon.setPort(Integer.parseInt(parsedHost[2]));
                    break;
                default:
                    throw new ConfigurationException("Could not parse provided server address: " + host
                            + ". Expected [CONNECTION_ALIAS:]<HOSTNAME>:<PORT>");
            }
            config.addConnectionEnd(serverCon);
        }
    }

}
