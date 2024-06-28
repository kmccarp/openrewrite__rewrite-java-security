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

import lombok.Value;
import lombok.With;
import org.openrewrite.Cursor;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.tree.Expression;
import org.openrewrite.java.tree.J;

import java.util.Optional;
import java.util.function.Predicate;

/**
 * Fixes the {@link java.io.File#File(String)} constructor call to use the multi-argument constructor when relevant.
 * <p>
 * For example:
 * <ul>
 *     <li>{@code new File("base" + File.separator + "test.txt")} becomes {@code new File("base", "test.txt")}</li>
 *     <li>{@code new File("base" + File.separatorChar + "test.txt")} becomes {@code new File("base", "test.txt")}</li>
 *     <li>{@code new File("base/" + "test.txt")} becomes {@code new File("base/", "test.txt")}</li>
 * </ul>
 */
public class FileConstructorFixVisitor<P> extends JavaIsoVisitor<P> {
    private static final MethodMatcher FILE_CONSTRUCTOR =
            new MethodMatcher("java.io.File <constructor>(java.lang.String)");

    private final JavaTemplate fileConstructorTemplate =
            JavaTemplate.builder("new File(#{any(java.lang.String)}, #{any(java.lang.String)})")
                    .imports("java.io.File")
                    .build();
    private final JavaTemplate stringAppendTemplate =
            JavaTemplate.builder("#{any()} + #{any(java.lang.String)}")
                    .contextSensitive()
                    .build();

    private final Predicate<Expression> overrideShouldBreakBefore;

    public FileConstructorFixVisitor(Predicate<Expression> overrideShouldBreakBefore) {
        this.overrideShouldBreakBefore = overrideShouldBreakBefore;
    }

    public FileConstructorFixVisitor() {
        this(e -> false);
    }

    @Override
    public J.NewClass visitNewClass(J.NewClass newClass, P p) {
        J.NewClass n = super.visitNewClass(newClass, p);
        Cursor cursor = new Cursor(getCursor().getParent(), n);
        if (FILE_CONSTRUCTOR.matches(n)) {
            Expression argument = n.getArguments().getFirst();
            if (argument instanceof J.Binary binary) {
                return (J.NewClass) computeNewArguments(new Cursor(cursor, binary))
                        .map(newArguments -> fileConstructorTemplate
                                .apply(cursor,
                                        n.getCoordinates().replace(),
                                        newArguments.first,
                                        newArguments.second
                                ))
                        .orElse(n);
            }
        }
        return n;
    }

    @Value
    @With
    static class NewArguments {
        Expression first;
        Expression second;
    }

    private Optional<NewArguments> computeNewArguments(Cursor cursor) {
        J.Binary binary = cursor.getValue();
        Expression newFirstArgument = null;
        if (overrideShouldBreakBefore.test(binary.getRight())) {
            newFirstArgument = binary.getLeft();
        }
        if (binary.getLeft() instanceof J.Binary) {
            J.Binary left = (J.Binary) binary.getLeft();
            if (left.getOperator() == J.Binary.Type.Addition) {
                if (FileSeparatorUtil.isFileSeparatorExpression(left.getRight())) {
                    newFirstArgument = left.getLeft();
                } else if (left.getLeft() instanceof J.Binary) {
                    return computeNewArguments(new Cursor(cursor, left))
                            .map(leftLeftNewArguments ->
                                    leftLeftNewArguments.withSecond(
                                            stringAppendTemplate.apply(cursor,
                                                    binary.getCoordinates().replace(),
                                                    leftLeftNewArguments.second,
                                                    binary.getRight())
                                    ));
                }
            }
        } else if (binary.getLeft() instanceof J.Literal) {
            J.Literal left = (J.Literal) binary.getLeft();
            if (left.getValue() instanceof String) {
                String leftValue = (String) left.getValue();
                if (leftValue.endsWith("/") || leftValue.endsWith("\\")) {
                    newFirstArgument = left;
                }
            }
        }
        return Optional.ofNullable(newFirstArgument)
                .map(first -> new NewArguments(first, binary.getRight()));
    }
}
