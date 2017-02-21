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

import de.rub.nds.tlsscanner.flaw.ConfigurationFlaw;
import de.rub.nds.tlsscanner.flaw.FlawLevel;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ProbeResult {
    private String probeName;
    private List<ResultValue> resultList;
    private List<ConfigurationFlaw> flawList;

    public ProbeResult(String probeName, List<ResultValue> resultList, List<ConfigurationFlaw> flawList) {
        this.probeName = probeName;
        this.resultList = resultList;
        this.flawList = flawList;
    }

    public String toJson() {
        StringBuilder builder = new StringBuilder();
        builder.append("\t\t\"" + probeName + "\": {\n");
        builder.append("\t\t\t\"result\": " + flawList.isEmpty() + "\n");

        builder.append("\t\t\t\"description\": \"" + getFlawString() + "\"\n");
        builder.append("\t\t}\n");
        return builder.toString();
    }

    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append(probeName);
        builder.append(":");
        builder.append("\n");
        for (ResultValue value : resultList) {
            builder.append(value.toString());
            builder.append("\n");
        }
        builder.append("Flaws:\n");
        builder.append(getFlawString());
        return builder.toString();
    }

    public String getFlawString() {
        StringBuilder builder = new StringBuilder();
        for (ConfigurationFlaw flaw : flawList) {
            builder.append(flaw.toString());
            builder.append("\n");
        }
        return builder.toString();
    }
}
