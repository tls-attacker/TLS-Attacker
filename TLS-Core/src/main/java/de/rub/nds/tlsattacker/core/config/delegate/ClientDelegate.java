/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import java.net.IDN;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.util.Arrays;
import org.bouncycastle.util.IPAddress;

public class ClientDelegate extends Delegate {

    private static final int DEFAULT_HTTPS_PORT = 443;

    @Parameter(names = "-connect", required = true, description = "Who to connect to. Syntax: localhost:4433")
    private String host = null;

    @Parameter(names = "-server_name", description = "Server name for the SNI extension.")
    private String sniHostname = null;

    private String extractedHost = null;

    private int extractedPort = -1;

    public ClientDelegate() {
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
        extractParameters();
    }

    @Override
    public void applyDelegate(Config config) {
        extractParameters();

        config.setDefaultRunningMode(RunningModeType.CLIENT);
        OutboundConnection con = config.getDefaultClientConnection();
        if (con == null) {
            con = new OutboundConnection();
            config.setDefaultClientConnection(con);
        }
        con.setPort(extractedPort);
        if (IPAddress.isValid(extractedHost)) {
            con.setIp(extractedHost);
            setHostname(config, extractedHost, con);
            if (sniHostname != null) {
                setHostname(config, sniHostname, con);
            }
        } else {
            if (sniHostname != null) {
                setHostname(config, sniHostname, con);
            } else {
                setHostname(config, extractedHost, con);
            }
            con.setIp(getIpForHost(extractedHost));
        }
    }

    public void setHostname(Config config, String hostname, OutboundConnection connection) {
        connection.setHostname(hostname);
        config.setDefaultSniHostnames(Arrays
            .asList(new ServerNamePair(config.getSniType().getValue(), hostname.getBytes(Charset.forName("ASCII")))));
    }

    private void extractParameters() {
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

        if (uri.getPort() <= 0) {
            extractedPort = DEFAULT_HTTPS_PORT;
        } else {
            extractedPort = uri.getPort();
        }
        extractedHost = uri.getHost();
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

    public String getExtractedHost() {
        if (host != null && extractedHost == null) {
            extractParameters();
        }
        return extractedHost;
    }

    public int getExtractedPort() {
        if (host != null && extractedPort == -1) {
            extractParameters();
        }
        return extractedPort;
    }
}
