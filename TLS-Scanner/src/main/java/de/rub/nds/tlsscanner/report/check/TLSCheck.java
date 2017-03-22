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
package de.rub.nds.tlsscanner.report.check;

import java.io.File;
import java.io.Serializable;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TLSCheck {

    private final CheckConfig config;
    private final boolean result;

    public TLSCheck(boolean result, CheckType type) {
        this.result = result;
        this.config = CheckConfigCache.getInstance().getCheckConfig(type);
    }

    public boolean isTransparentIfPassed() {
        return config.isTransparentIfPassed();
    }

    public String getName() {
        if (result) {
            return config.getUnsuccessName();
        } else {
            return config.getSuccessName();
        }

    }

    public boolean isResult() {
        return result;
    }

    public String getDescription() {
        if (result) {
            return config.getUnsuccessDescription();
        } else {
            return config.getSuccessDescription();
        }
    }

    @Override
    public String toString() {
        return "TLSCheck{" + "name=" + getName() + ", descption=" + getDescription() + ", result=" + result + '}';
    }
}
