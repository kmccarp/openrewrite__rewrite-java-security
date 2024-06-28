/*
 * Copyright 2024 the original author or authors.
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
package org.openrewrite.java.security.spring;

import org.openrewrite.ExecutionContext;
import org.openrewrite.Recipe;
import org.openrewrite.Tree;
import org.openrewrite.TreeVisitor;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaSourceFile;
import org.openrewrite.java.tree.TypeUtils;
import org.openrewrite.marker.SearchResult;
import org.openrewrite.xml.XPathMatcher;
import org.openrewrite.xml.XmlIsoVisitor;
import org.openrewrite.xml.tree.Xml;

import java.time.Duration;
import java.util.Collections;
import java.util.Set;

public class InsecureSpringServiceExporter extends Recipe {

    @Override
    public String getDisplayName() {
        return "Secure Spring service exporters";
    }

    @Override
    public String getDescription() {
        return """
               The default Java deserialization mechanism is available via `ObjectInputStream` \
               class. This mechanism is known to be vulnerable. If an attacker can make an \
               application deserialize malicious data, it may result in arbitrary code execution.
               
               Spring’s `RemoteInvocationSerializingExporter` uses the default Java deserialization \
               mechanism to parse data. As a result, all classes that extend it are vulnerable to \
               deserialization attacks. The Spring Framework contains at least `HttpInvokerServiceExporter` \
               and `SimpleHttpInvokerServiceExporter` that extend `RemoteInvocationSerializingExporter`. \
               These exporters parse data from the HTTP body using the unsafe Java deserialization mechanism.
               
               See the full [blog post](https://blog.gypsyengineer.com/en/security/detecting-dangerous-spring-exporters-with-codeql.html) \
               by Artem Smotrakov on CVE-2016-1000027 from which the above description is excerpted.\
               """;
    }

    @Override
    public Set<String> getTags() {
        return Collections.singleton("CVE-2016-1000027");
    }

    @Override
    public @Nullable Duration getEstimatedEffortPerOccurrence() {
        return Duration.ofMinutes(15);
    }

    @Override
    public TreeVisitor<?, ExecutionContext> getVisitor() {
        return new TreeVisitor<Tree, ExecutionContext>() {
            @Override
            public @Nullable Tree preVisit(Tree tree, ExecutionContext ctx) {
                if (tree instanceof JavaSourceFile) {
                    return findJavaUses().visit(tree, ctx, getCursor().getParentOrThrow());
                } else if (tree instanceof Xml.Document) {
                    return findXmlUses().visit(tree, ctx, getCursor().getParentOrThrow());
                }
                return super.preVisit(tree, ctx);
            }
        };
    }

    private static JavaIsoVisitor<ExecutionContext> findJavaUses() {
        return new JavaIsoVisitor<ExecutionContext>() {
            @Override
            public J.MethodDeclaration visitMethodDeclaration(J.MethodDeclaration method, ExecutionContext ctx) {
                if (method.getReturnTypeExpression() != null &&
                    TypeUtils.isAssignableTo("org.springframework.remoting.rmi.RemoteInvocationSerializingExporter", method.getReturnTypeExpression().getType())) {
                    return method.withReturnTypeExpression(SearchResult.found(method.getReturnTypeExpression()));
                }
                return super.visitMethodDeclaration(method, ctx);
            }

            @Override
            public J.ClassDeclaration visitClassDeclaration(J.ClassDeclaration classDecl, ExecutionContext ctx) {
                if (TypeUtils.isAssignableTo("org.springframework.remoting.rmi.RemoteInvocationSerializingExporter",
                        classDecl.getType())) {
                    return SearchResult.found(classDecl);
                }
                return super.visitClassDeclaration(classDecl, ctx);
            }
        };
    }

    private static XmlIsoVisitor<ExecutionContext> findXmlUses() {
        XPathMatcher bean = new XPathMatcher("/beans/bean");
        return new XmlIsoVisitor<ExecutionContext>() {
            @Override
            public Xml.Tag visitTag(Xml.Tag tag, ExecutionContext ctx) {
                if (bean.matches(getCursor())) {
                    if (tag.getAttributes().stream()
                            .anyMatch(a -> "class".equals(a.getKeyAsString()) && (
                                    "org.springframework.remoting.httpinvoker.HttpInvokerServiceExporter".equals(a.getValueAsString())) ||
                                           "org.springframework.remoting.httpinvoker.SimpleHttpInvokerServiceExporter".equals(a.getValueAsString())
                            )) {
                        return SearchResult.found(tag);
                    }
                }
                return super.visitTag(tag, ctx);
            }
        };
    }
}
