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
package org.openrewrite.java.security;

import org.openrewrite.ExecutionContext;
import org.openrewrite.Preconditions;
import org.openrewrite.Recipe;
import org.openrewrite.TreeVisitor;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.search.UsesMethod;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.TypeUtils;
import org.openrewrite.marker.SearchResult;

import java.util.Set;

import static java.util.Collections.singleton;

public class ImproperPrivilegeManagement extends Recipe {

    @Override
    public String getDisplayName() {
        return "Improper privilege management";
    }

    @Override
    public String getDescription() {
        return """
               Marking code as privileged enables a piece of trusted code to temporarily \
               enable access to more resources than are available directly to the code \
               that called it.\
               """;
    }

    @Override
    public Set<String> getTags() {
        return singleton("CWE-269");
    }

    @Override
    public TreeVisitor<?, ExecutionContext> getVisitor() {
        MethodMatcher privilegedMethod = new MethodMatcher("java.security.AccessController doPrivileged(..)");
        return Preconditions.check(new UsesMethod<>(privilegedMethod), new JavaIsoVisitor<ExecutionContext>() {
            @Override
            public J.ClassDeclaration visitClassDeclaration(J.ClassDeclaration classDecl, ExecutionContext ctx) {
                if (TypeUtils.isAssignableTo("java.security.PrivilegedAction", classDecl.getType())) {
                    return SearchResult.found(classDecl);
                }
                return super.visitClassDeclaration(classDecl, ctx);
            }

            @Override
            public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, ExecutionContext ctx) {
                if (privilegedMethod.matches(method)) {
                    return SearchResult.found(method);
                }
                return super.visitMethodInvocation(method, ctx);
            }
        });
    }
}
