/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsattacker.testsuite.impl;

import de.rub.nds.tlsattacker.tls.config.GeneralConfig;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public abstract class TestSuite {

    GeneralConfig generalConfig;

    public TestSuite(GeneralConfig config) {
	this.generalConfig = config;
    }

    public abstract boolean startTests();
}
