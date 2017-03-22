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

import de.rub.nds.tlsscanner.exception.UnloadableConfigException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXB;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CheckConfigSerializer {

    public static void serialize(CheckConfig config, File file) {
        JAXB.marshal(config, file);
    }

    public static CheckConfig deserialize(File file) {
        try {
            return JAXB.unmarshal(new FileInputStream(file), CheckConfig.class);
        } catch (FileNotFoundException ex) {
            throw new UnloadableConfigException("Could not load: " + file.getAbsolutePath(), ex);
        }
    }
}
