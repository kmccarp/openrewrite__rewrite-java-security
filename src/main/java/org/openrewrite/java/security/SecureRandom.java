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
package org.openrewrite.java.security;

import org.openrewrite.*;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.search.InJavaSourceSet;
import org.openrewrite.java.search.UsesType;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.TypeUtils;

import java.util.Collections;
import java.util.Set;

public class SecureRandom extends Recipe {

    @Override
    public String getDisplayName() {
        return "Secure random";
    }

    @Override
    public String getDescription() {
        return """
                Use cryptographically secure Pseudo Random Number Generation in the "main" source set. \
                Replaces instantiation of `java.util.Random` with `java.security.SecureRandom`.\
                """;
    }

    @Override
    public Set<String> getTags() {
        return Collections.singleton("RSPEC-S2245");
    }

    @Override
    public TreeVisitor<?, ExecutionContext> getVisitor() {
        return Preconditions.check(Preconditions.and(
                new UsesType<>("java.util.Random", false),
                new InJavaSourceSet<>("main")
        ), new JavaIsoVisitor<ExecutionContext>() {
            @Override
            public J.NewClass visitNewClass(J.NewClass newClass, ExecutionContext ctx) {
                J.NewClass n = super.visitNewClass(newClass, ctx);
                if (TypeUtils.isOfClassType(newClass.getType(), "java.util.Random")) {
                    maybeAddImport("java.security.SecureRandom");
                    maybeRemoveImport("java.util.Random");
                    return JavaTemplate.builder("new SecureRandom()")
                            .imports("java.security.SecureRandom")
                            .build()
                            .apply(new Cursor(getCursor().getParent(), n), newClass.getCoordinates().replace());
                }
                return n;
            }
        });
    }
}
