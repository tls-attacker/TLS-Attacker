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
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import java.net.IDN;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import org.bouncycastle.util.IPAddress;

public class ClientDelegate extends Delegate {

    private final static int DEFAULT_HTTPS_PORT = 443;

    @Parameter(names = "-connect", required = true, description = "Who to connect to. Syntax: localhost:4433")
    private String host = null;

    @Parameter(names = "-server_name", description = "Servername for the SNI extension.")
    private String sniHostname = null;

    public ClientDelegate() {
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    @Override
    public void applyDelegate(Config config) {
        config.setDefaulRunningMode(RunningModeType.CLIENT);

        if (host == null) {
            // Though host is a required parameter we can get here if
            // we call applyDelegate manually, e.g. in tests.
            throw new ParameterException("Could not parse provided host: " + host);
        }
        // Remove any provided protocols
        String[] split = host.split("://");
        if (split.length > 0) {
            host = split[split.length - 1];
        }
        host = IDN.toASCII(host);
        URI uri;
        try {
            // Add a dummy protocol
            uri = new URI("my://" + host);
        } catch (URISyntaxException ex) {
            throw new ParameterException("Could not parse host '" + host + "'", ex);
        }
        if (uri.getHost() == null) {
            throw new ParameterException("Provided host seems invalid:" + host);
        }
        OutboundConnection con = config.getDefaultClientConnection();
        if (con == null) {
            con = new OutboundConnection();
            config.setDefaultClientConnection(con);
        }
        if (uri.getPort() <= 0) {
            con.setPort(DEFAULT_HTTPS_PORT);
        } else {
            con.setPort(uri.getPort());
        }
        if (IPAddress.isValid(uri.getHost())) {
            con.setIp(uri.getHost());
            if (sniHostname != null) {
                con.setHostname(sniHostname);
            } else {
                con.setHostname(getHostForIp(uri.getHost()));
            }
        } else {
            if (sniHostname != null) {
                con.setHostname(sniHostname);
            } else {
                con.setHostname(uri.getHost());
            }
            con.setIp(getIpForHost(uri.getHost()));
        }

    }

    private String getIpForHost(String host) {
        try {
            InetAddress inetAddress = InetAddress.getByName(host);
            return inetAddress.getHostAddress();
        } catch (UnknownHostException ex) {
            LOGGER.warn("Could not resolve host \"" + host + "\" returning anyways", ex);
            return host;
        }
    }

    private String getHostForIp(String ip) {
        try {
            return InetAddress.getByName(ip).getCanonicalHostName();
        } catch (UnknownHostException ex) {
            LOGGER.warn("Could not perform reverse DNS for \"" + ip + "\"", ex);
            return ip;
        }
    }

    public String getSniHostname() {
        return sniHostname;
    }

    public void setSniHostname(String sniHostname) {
        this.sniHostname = sniHostname;
    }
}
