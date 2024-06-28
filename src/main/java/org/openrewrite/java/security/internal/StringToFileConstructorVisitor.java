/*
 * Copyright 2021 the original author or authors.
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
package org.openrewrite.java.security.internal;

import fj.data.Option;
import org.openrewrite.analysis.dataflow.DataFlowNode;
import org.openrewrite.analysis.dataflow.ExternalSinkModels;
import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.JavaVisitor;
import org.openrewrite.java.tree.Expression;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.TypeUtils;

import java.util.function.Supplier;

/**
 * Replaces constructor calls like
 * {@link java.io.FileOutputStream#FileOutputStream(String)} with
 * {@link java.io.FileOutputStream#FileOutputStream(java.io.File)} by adding the required
 * {@link java.io.File} constructor call.
 */
public class StringToFileConstructorVisitor<P> extends JavaVisitor<P> {
    private final JavaTemplate fileConstructorTemplate =
            JavaTemplate.builder("new File(#{any(java.lang.String)})")
                    .imports("java.io.File").build();

    private final Supplier<FileConstructorFixVisitor<P>> fileConstructorFixVisitorFactory;

    public StringToFileConstructorVisitor(Supplier<FileConstructorFixVisitor<P>> fileConstructorFixVisitorFactory) {
        this.fileConstructorFixVisitorFactory = fileConstructorFixVisitorFactory;
    }

    public StringToFileConstructorVisitor() {
        this(FileConstructorFixVisitor::new);
    }

    @Override
    public Expression visitExpression(Expression expression, P p) {
        return DataFlowNode
                .of(getCursor())
                .filter(n -> ExternalSinkModels.instance().isSinkNode(n, "create-file"))
                .bind(__ -> {
                    J.NewClass parentConstructor = getCursor().firstEnclosing(J.NewClass.class);
                    if (parentConstructor != null &&
                        parentConstructor.getArguments().getFirst() == expression &&
                        TypeUtils.isString(expression.getType())
                    ) {
                        Expression replacementConstructor =
                                fileConstructorTemplate.apply(
                                        getCursor(),
                                        expression.getCoordinates().replace(),
                                        expression
                                );
                        return Option
                                .some((Expression) fileConstructorFixVisitorFactory
                                        .get()
                                        .visitNonNull(
                                                replacementConstructor,
                                                p,
                                                getCursor()
                                        ));
                    }
                    return Option.none();
                })
                .orSome(expression);
    }
}
