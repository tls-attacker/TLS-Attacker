/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner;

import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.check.CheckConfig;
import de.rub.nds.tlsscanner.report.check.CheckConfigSerializer;
import java.io.File;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
class Main {
    public static void main(String args[]) {
        TLSScanner scanner = new TLSScanner("google.com");
        SiteReport report = scanner.scan();
        System.out.println(report.getStringReport());
    }
}
