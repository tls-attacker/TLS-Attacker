/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.proxy;

import com.beust.jcommander.Parameter;

public class ProxyConfig {

    @Parameter(names = "-port", required = true, description = "The Port the proxy should listen to (Default 9090)")
    private int listeningPort = 1080;

    @Parameter(names = "-config", description = "This parameter allows you to specify a default TlsConfig")
    private String defaultConfig = null;

    @Parameter(names = "-clientHello", description = "This parameter allows you to specify a default ClientHello")
    private String clientHello = null;

    @Parameter(names = "-proxyServerCertificate", required = true,
        description = "The certificate the proxy faces to incoming clients (JKS)")
    private String serverCertificate = null;

    @Parameter(names = "-alias", required = true, description = "The alias of the certificate")
    private String alias = null;

    @Parameter(names = "-password", required = true, description = "The password of the certificate")
    private String password = null;

    public ProxyConfig() {
    }

    public int getListeningPort() {
        return listeningPort;
    }

    public void setListeningPort(int listeningPort) {
        this.listeningPort = listeningPort;
    }

    public String getDefaultConfig() {
        return defaultConfig;
    }

    public void setDefaultConfig(String defaultConfig) {
        this.defaultConfig = defaultConfig;
    }

    public String getClientHello() {
        return clientHello;
    }

    public void setClientHello(String clientHello) {
        this.clientHello = clientHello;
    }

    public String getServerCertificate() {
        return serverCertificate;
    }

    public void setServerCertificate(String serverCertificate) {
        this.serverCertificate = serverCertificate;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
