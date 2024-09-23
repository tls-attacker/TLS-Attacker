/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.proxy;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.core.util.ProviderUtil;
import java.io.IOException;

public class Main {

    public static void main(String[] args) throws IOException {
        ProviderUtil.addBouncyCastleProvider();
        ProxyConfig proxyConfig = new ProxyConfig();
        JCommander jc = new JCommander(proxyConfig);
        jc.parse(args);
        HttpsProxy proxy = new HttpsProxy(proxyConfig);
        proxy.start();
    }
}
