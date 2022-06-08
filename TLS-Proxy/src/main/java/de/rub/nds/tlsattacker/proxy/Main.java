/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.proxy;

import com.beust.jcommander.JCommander;
import java.io.IOException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

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
