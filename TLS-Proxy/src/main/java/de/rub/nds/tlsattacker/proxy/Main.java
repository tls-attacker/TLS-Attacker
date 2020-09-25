/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsattacker.proxy;

import com.beust.jcommander.JCommander;
import java.io.IOException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class Main {

    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());
        ProxyConfig proxyConfig = new ProxyConfig();
        JCommander jc = new JCommander(proxyConfig);
        jc.parse(args);
        HttpsProxy proxy = new HttpsProxy(proxyConfig);
        proxy.start();
    }
}
