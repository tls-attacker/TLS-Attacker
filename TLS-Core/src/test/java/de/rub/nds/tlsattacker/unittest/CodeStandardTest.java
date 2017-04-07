/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.unittest;

import com.openpojo.reflection.PojoClass;
import com.openpojo.reflection.impl.PojoClassFactory;
import com.openpojo.validation.Validator;
import com.openpojo.validation.ValidatorBuilder;
import com.openpojo.validation.rule.impl.GetterMustExistRule;
import com.openpojo.validation.rule.impl.NoFieldShadowingRule;
import com.openpojo.validation.rule.impl.NoNestedClassRule;
import com.openpojo.validation.rule.impl.NoPrimitivesRule;
import com.openpojo.validation.rule.impl.NoPublicFieldsExceptStaticFinalRule;
import com.openpojo.validation.rule.impl.NoStaticExceptFinalRule;
import com.openpojo.validation.rule.impl.SerializableMustHaveSerialVersionUIDRule;
import com.openpojo.validation.rule.impl.SetterMustExistRule;
import com.openpojo.validation.rule.impl.TestClassMustBeProperlyNamedRule;
import com.openpojo.validation.test.impl.DefaultValuesNullTester;
import com.openpojo.validation.test.impl.GetterTester;
import com.openpojo.validation.test.impl.SetterTester;
import java.util.List;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class CodeStandardTest {
    // // Configured for expectation, so we know when a class gets added or
    // // removed.
    //
    // // The package to test
    // private static final String POJO_PACKAGE = "com.openpojo.samplepojo";
    //
    // private List<PojoClass> pojoClasses;
    // private Validator validator;
    //
    // @Before
    // public void setup() {
    // pojoClasses = PojoClassFactory.getPojoClassesRecursively("de", null);
    // validator = ValidatorBuilder.create()
    // // Don't shadow parent's field names.
    // .with(new NoFieldShadowingRule())
    // // What about public fields, use one of the following rules
    // // allow them only if they are static and final.
    // .with(new NoPublicFieldsExceptStaticFinalRule())
    // // Or you can be more restrictive and not allow ANY public
    // // fields in a Pojo.
    // // pojoValidator.addRule(new NoPublicFieldsRule());
    //
    // // Finally, what if you are testing your Testing code?
    // // Make sure your tests are properly named
    // .with(new TestClassMustBeProperlyNamedRule()).build();
    // for (int i = 0; i < pojoClasses.size(); i++) {
    // PojoClass get = pojoClasses.get(i);
    //
    // }
    //
    // }
    //
    // @Test
    // public void testPojoStructureAndBehavior() {
    //
    // validator.validate(pojoClasses);
    // }
}
