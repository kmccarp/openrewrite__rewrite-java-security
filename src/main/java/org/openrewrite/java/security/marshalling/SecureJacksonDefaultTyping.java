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
package org.openrewrite.java.security.marshalling;

import org.openrewrite.ExecutionContext;
import org.openrewrite.Recipe;
import org.openrewrite.TreeVisitor;
import org.openrewrite.internal.ListUtils;
import org.openrewrite.java.JavaParser;
import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.JavaVisitor;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.tree.Expression;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaType;
import org.openrewrite.java.tree.TypeUtils;

import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static java.util.Collections.emptyList;

public class SecureJacksonDefaultTyping extends Recipe {

    @Override
    public String getDisplayName() {
        return "Secure the use of Jackson default typing";
    }

    @Override
    public String getDescription() {
        return "See the [blog post](https://cowtowncoder.medium.com/on-jackson-cves-dont-panic-here-is-what-you-need-to-know-54cd0d6e8062) on this subject.";
    }

    @Override
    public Duration getEstimatedEffortPerOccurrence() {
        return Duration.ofMinutes(10);
    }

    @Override
    public Set<String> getTags() {
        return new HashSet<>(Arrays.asList("CWE-502", "CWE-94"));
    }

    @Override
    public TreeVisitor<?, ExecutionContext> getVisitor() {
        MethodMatcher enableDefaultTyping = new MethodMatcher("com.fasterxml.jackson.databind.ObjectMapper enableDefaultTyping(..)", true);
        return new JavaVisitor<ExecutionContext>() {
            @Override
            public J visitMethodInvocation(J.MethodInvocation method, ExecutionContext ctx) {
                if (enableDefaultTyping.matches(method)) {
                    JavaType.Method methodType = method.getMethodType();
                    assert methodType != null;

                    if (methodType.getDeclaringType().getMethods().stream().anyMatch(m -> "activateDefaultTyping".equals(m.getName()))) {
                        // Jackson version is 2.10 or above
                        maybeAddImport("com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator");

                        StringBuilder template = new StringBuilder("#{any(com.fasterxml.jackson.databind.ObjectMapper)}.activateDefaultTyping(BasicPolymorphicTypeValidator.builder().build()");
                        for (Expression arg : method.getArguments()) {
                            JavaType.FullyQualified argType = TypeUtils.asFullyQualified(arg.getType());
                            if (argType != null) {
                                template.append(",#{any(").append(argType.getFullyQualifiedName()).append(")}");
                            }
                        }
                        template.append(')');

                        return JavaTemplate
                                .builder(template.toString())
                                .imports("com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator")
                                .javaParser(JavaParser.fromJavaVersion()
                                        .classpathFromResources(ctx, "jackson-databind", "jackson-core"))
                                .build()
                                .apply(getCursor(),
                                        method.getCoordinates().replace(),
                                        ListUtils.concat(method.getSelect(), method.getArguments().getFirst() instanceof J.Empty ? emptyList() : method.getArguments()).toArray());
                    }
                }

                return super.visitMethodInvocation(method, ctx);
            }
        };
    }
}
