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

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.openrewrite.Cursor;
import org.openrewrite.analysis.InvocationMatcher;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.tree.Expression;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaCoordinates;
import org.openrewrite.java.tree.Statement;

import java.util.Set;

@AllArgsConstructor
@Getter
public abstract class XmlFactoryInsertVisitor<P> extends JavaIsoVisitor<P> {
    private final StringBuilder template = new StringBuilder();
    private final J.Block scope;
    private final XmlFactoryVariable factoryVariable;
    private final InvocationMatcher factoryInstanceMatcher;
    private final InvocationMatcher factoryMethodCallMatcher;
    private final Set<String> imports;

    public abstract void updateTemplate();

    protected String getFactoryVariableName() {
        return factoryVariable.getVariableName();
    }

    private Statement getInsertStatement(J.Block b) {
        Statement beforeStatement = null;
        if (b.isScope(scope)) {
            for (int i = b.getStatements().size() - 2; i > -1; i--) {
                Statement st = b.getStatements().get(i);
                Statement stBefore = b.getStatements().get(i + 1);
                if (st instanceof J.MethodInvocation m) {
                    if (Expression.unwrap(m.getSelect()) instanceof J.Identifier &&
                        (factoryInstanceMatcher.matches(m) || factoryMethodCallMatcher.matches(m))
                    ) {
                        J.Identifier ident = (J.Identifier) m.getSelect().unwrap();
                        if (ident.getSimpleName().equals(getFactoryVariableName())) {
                            beforeStatement = stBefore;
                        }
                    }
                } else if (st instanceof J.VariableDeclarations vd) {
                    if (vd.getVariables().getFirst().getInitializer() instanceof J.MethodInvocation) {
                        String varName = vd.getVariables().getFirst().getSimpleName();
                        J.MethodInvocation m = (J.MethodInvocation) vd.getVariables().getFirst().getInitializer();
                        if (m != null && varName.equals(getFactoryVariableName()) && factoryInstanceMatcher.matches(m)) {
                            beforeStatement = stBefore;
                        }
                    }
                }
            }
        }
        return beforeStatement;
    }

    private JavaCoordinates getInsertCoordinates(J.Block b, Statement s) {
        return s != null ? s.getCoordinates().before() : b.getCoordinates().lastStatement();
    }

    private J.Block updateBlock(J.Block b, Statement beforeStatement) {
        if (getCursor().getParent() != null && getCursor().getParent().getValue() instanceof J.ClassDeclaration) {
            if (factoryVariable.isStatic()) {
                template.insert(0, "static {\n");
            } else {
                template.insert(0, "{\n");
            }
            template.append("\n}");
        }
        b = JavaTemplate
                .builder(template.toString())
                .imports(imports.toArray(new String[0]))
                .contextSensitive()
                .build()
                .apply(new Cursor(getCursor().getParent(), b), getInsertCoordinates(b, beforeStatement));
        imports.forEach(this::maybeAddImport);
        return b;
    }

    @Override
    public J.Block visitBlock(J.Block block, P ctx) {
        J.Block b = super.visitBlock(block, ctx);
        Statement beforeStatement = getInsertStatement(b);
        if (b.isScope(scope)) {
            updateTemplate();
            if (template.length() != 0) {
                b = updateBlock(b, beforeStatement);
            }
        }
        return b;
    }
}
