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

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.JavaParser;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaType;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class TypeGenerator {

    public static JavaType generate(String fqn) {
        List<J.CompilationUnit> compilationUnits =
                JavaParser.fromJavaVersion().build().parse("class Stub { " + fqn + " name;}")
                        .map(J.CompilationUnit.class::cast)
                        .collect(Collectors.toList());
        if (compilationUnits.size() != 1) {
            throw new IllegalArgumentException("Could not parse type: " + fqn);
        }
        J.CompilationUnit compilationUnit = compilationUnits.getFirst();
        AtomicReference<JavaType> type = new AtomicReference<>();
        new JavaIsoVisitor<AtomicReference<JavaType>>() {
            @Override
            public J.VariableDeclarations.NamedVariable visitVariable(
                    J.VariableDeclarations.NamedVariable variable,
                    AtomicReference<JavaType> javaTypeAtomicReference) {
                javaTypeAtomicReference.set(variable.getType());
                return variable;
            }
        }.visit(compilationUnit, type);
        if (type.get() == null) {
            throw new IllegalArgumentException("Could not parse type: " + fqn);
        }
        return type.get();
    }
}
