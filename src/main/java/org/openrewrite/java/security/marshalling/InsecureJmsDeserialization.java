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
package org.openrewrite.java.security.marshalling;

import org.openrewrite.ExecutionContext;
import org.openrewrite.Preconditions;
import org.openrewrite.Recipe;
import org.openrewrite.TreeVisitor;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.search.UsesMethod;
import org.openrewrite.java.tree.J;
import org.openrewrite.marker.SearchResult;

import java.util.Set;

import static java.util.Collections.singleton;

public class InsecureJmsDeserialization extends Recipe {

    @Override
    public String getDisplayName() {
        return "Insecure JMS deserialization";
    }

    @Override
    public String getDescription() {
        return """
               JMS `Object` messages depend on Java Serialization for marshalling/unmarshalling of the \
               message payload when `ObjectMessage#getObject` is called. Deserialization of untrusted \
               data can lead to security flaws.\
               """;
    }

    @Override
    public Set<String> getTags() {
        return singleton("CWE-502");
    }

    @Override
    public TreeVisitor<?, ExecutionContext> getVisitor() {
        MethodMatcher getObject = new MethodMatcher("javax.jms.ObjectMessage getObject()");
        MethodMatcher onMessage = new MethodMatcher("javax.jms.MessageListener onMessage(..)", true);

        return Preconditions.check(Preconditions.or(new UsesMethod<>(getObject), new UsesMethod<>(onMessage)), new JavaIsoVisitor<ExecutionContext>() {
            @Override
            public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, ExecutionContext ctx) {
                J.MethodInvocation m = super.visitMethodInvocation(method, ctx);
                J.MethodDeclaration enclosingMethod = getCursor().firstEnclosing(J.MethodDeclaration.class);
                if (getObject.matches(method) && enclosingMethod != null && onMessage.matches(enclosingMethod.getMethodType())) {
                    return SearchResult.found(method);
                }
                return m;
            }
        });
    }
}
