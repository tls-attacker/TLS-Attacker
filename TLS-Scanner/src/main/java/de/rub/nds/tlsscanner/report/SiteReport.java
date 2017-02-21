/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report;

import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class SiteReport {

    private List<ProbeResult> resultList;
    private String host;

    public SiteReport(String host, List<ProbeResult> resultList) {
        this.resultList = resultList;
        this.host = host;
    }

    // JSon magic
    public String getJsonReport() {
        StringBuilder builder = new StringBuilder();
        builder.append("{\n");
        builder.append("\t \"checks\": [\n");
        for (ProbeResult result : resultList) {
            builder.append(result.toJson());
        }
        builder.append("\t]\n");
        builder.append("}\n");
        return builder.toString();
    }

    public String getStringReport() {
        StringBuilder builder = new StringBuilder();
        builder.append("Report for ");
        builder.append(host);
        builder.append("\n");
        for (ProbeResult result : resultList) {
            builder.append(result.toString());
            builder.append("\n");
        }
        return builder.toString();
    }

    @Override
    public String toString() {
        return getStringReport();
    }

}
