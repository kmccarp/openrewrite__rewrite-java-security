/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.openrewrite.java.security.xml;

import org.openrewrite.Cursor;
import org.openrewrite.ExecutionContext;
import org.openrewrite.Preconditions;
import org.openrewrite.TreeVisitor;
import org.openrewrite.analysis.InvocationMatcher;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.search.UsesType;
import org.openrewrite.java.tree.J;

import javax.xml.XMLConstants;

public class TransformerFactoryFixVisitor<P> extends XmlFactoryVisitor<P> {
    static final InvocationMatcher TRANSFORMER_FACTORY_INSTANCE = new MethodMatcher("javax.xml.transform.TransformerFactory new*()")::matches;
    static final InvocationMatcher TRANSFORMER_FACTORY_SET_ATTRIBUTE = new MethodMatcher("javax.xml.transform.TransformerFactory setAttribute(java.lang.String, ..)")::matches;
    static final InvocationMatcher TRANSFORMER_FACTORY_SET_FEATURE = new MethodMatcher("javax.xml.transform.TransformerFactory setFeature(java.lang.String, ..)")::matches;

    private static final String TRANSFORMER_FACTORY_FQN = "javax.xml.transform.TransformerFactory";
    private static final String ACCESS_EXTERNAL_DTD_NAME = "ACCESS_EXTERNAL_DTD";
    private static final String ACCESS_EXTERNAL_STYLESHEET_NAME = "ACCESS_EXTERNAL_STYLESHEET";
    private static final String FEATURE_SECURE_PROCESSING_NAME = "FEATURE_SECURE_PROCESSING";

    private static final String TRANSFORMER_FACTORY_INITIALIZATION_METHOD = "transformer-factory-initialization-method";
    private static final String TRANSFORMER_FACTORY_VARIABLE_NAME = "transformer-factory-variable-name";

    private static final String DISALLOW_MODIFY_FLAG = "DISALLOW_MODIFY_FLAG";

    public TransformerFactoryFixVisitor(ExternalDTDAccumulator acc) {
        super(
                TRANSFORMER_FACTORY_INSTANCE,
                TRANSFORMER_FACTORY_FQN,
                TRANSFORMER_FACTORY_INITIALIZATION_METHOD,
                TRANSFORMER_FACTORY_VARIABLE_NAME,
                acc
        );
    }

    @Override
    public J.ClassDeclaration visitClassDeclaration(J.ClassDeclaration classDecl, P ctx) {
        J.ClassDeclaration cd = super.visitClassDeclaration(classDecl, ctx);
        for (int i = 1; i <= getCount(); i++) {
            Cursor supportsExternalCursor = getCursor().getMessage(ACCESS_EXTERNAL_DTD_NAME + i);
            Cursor supportsStylesheetCursor = getCursor().getMessage(ACCESS_EXTERNAL_STYLESHEET_NAME + i);
            Cursor supportsFeatureSecureProcessing = getCursor().getMessage(FEATURE_SECURE_PROCESSING_NAME + i);
            Cursor initializationCursor = getCursor().getMessage(TRANSFORMER_FACTORY_INITIALIZATION_METHOD + i);
            Cursor disallowModifyFlagCursor = getCursor().getMessage(DISALLOW_MODIFY_FLAG + i);
            XmlFactoryVariable transformerFactoryVariable = getCursor().getMessage(TRANSFORMER_FACTORY_VARIABLE_NAME + i);

            Cursor setAttributeBlockCursor = null;
            if (supportsExternalCursor == null && supportsStylesheetCursor == null && supportsFeatureSecureProcessing == null) {
                setAttributeBlockCursor = initializationCursor;
            } else if ((supportsExternalCursor == null ^ supportsStylesheetCursor == null) || (supportsStylesheetCursor == null ^ supportsFeatureSecureProcessing == null)) {
                if (supportsExternalCursor != null) {
                    setAttributeBlockCursor = supportsExternalCursor;
                } else if (supportsStylesheetCursor != null) {
                    setAttributeBlockCursor = supportsStylesheetCursor;
                } else {
                    setAttributeBlockCursor = supportsFeatureSecureProcessing;
                }
            }
            if (disallowModifyFlagCursor == null && setAttributeBlockCursor != null && transformerFactoryVariable != null) {
                doAfterVisit(new TransformerFactoryInsertAttributeStatementVisitor<>(
                        setAttributeBlockCursor.getValue(),
                        transformerFactoryVariable,
                        supportsExternalCursor == null,
                        supportsStylesheetCursor == null,
                        supportsFeatureSecureProcessing == null
                ));
            }
        }
        return cd;
    }

    @Override
    public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, P ctx) {
        J.MethodInvocation m = super.visitMethodInvocation(method, ctx);
        if (TRANSFORMER_FACTORY_SET_ATTRIBUTE.matches(m) && m.getArguments().getFirst() instanceof J.FieldAccess) {
            // If either attribute value is not equal to the empty string, do not make any changes
            if (m.getArguments().get(1) instanceof J.Literal) {
                J.Literal string = (J.Literal) m.getArguments().get(1);
                assert string.getValue() != null;
                if (!(((String) string.getValue()).isEmpty())) {
                    addMessage(DISALLOW_MODIFY_FLAG);
                }
            }
            J.FieldAccess fa = (J.FieldAccess) m.getArguments().getFirst();
            if (ACCESS_EXTERNAL_DTD_NAME.equals(fa.getSimpleName())) {
                addMessage(ACCESS_EXTERNAL_DTD_NAME);
            } else if (ACCESS_EXTERNAL_STYLESHEET_NAME.equals(fa.getSimpleName())) {
                addMessage(ACCESS_EXTERNAL_STYLESHEET_NAME);
            }
        } else if (TRANSFORMER_FACTORY_SET_FEATURE.matches(m)) {
            // If FEATURE_SECURE_PROCESSING is set to false, do not make any changes
            if (m.getArguments().get(1) instanceof J.Literal) {
                J.Literal bool = (J.Literal) m.getArguments().get(1);
                assert bool.getValue() != null;
                if (Boolean.FALSE.equals(bool.getValue())) {
                    addMessage(DISALLOW_MODIFY_FLAG);
                }
            }
            if (m.getArguments().getFirst() instanceof J.FieldAccess) {
                J.FieldAccess fa = (J.FieldAccess) m.getArguments().getFirst();
                if (FEATURE_SECURE_PROCESSING_NAME.equals(fa.getSimpleName())) {
                    addMessage(FEATURE_SECURE_PROCESSING_NAME);
                }
            } else if (m.getArguments().getFirst() instanceof J.Literal) {
                J.Literal literal = (J.Literal) m.getArguments().getFirst();
                if (XMLConstants.FEATURE_SECURE_PROCESSING.equals(literal.getValue())) {
                    addMessage(FEATURE_SECURE_PROCESSING_NAME);
                }
            }
        }
        return m;
    }

    public static TreeVisitor<?, ExecutionContext> create(ExternalDTDAccumulator acc) {
        return Preconditions.check(new UsesType<>(TRANSFORMER_FACTORY_FQN, true), new TransformerFactoryFixVisitor<>(acc));
    }
}
