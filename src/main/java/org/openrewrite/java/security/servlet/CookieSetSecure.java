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
package org.openrewrite.java.security.servlet;

import fj.data.Option;
import org.openrewrite.*;
import org.openrewrite.analysis.dataflow.DataFlowNode;
import org.openrewrite.analysis.dataflow.DataFlowSpec;
import org.openrewrite.analysis.dataflow.Dataflow;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.JavaParser;
import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.search.UsesMethod;
import org.openrewrite.java.tree.Expression;
import org.openrewrite.java.tree.J;

import java.util.Collections;
import java.util.Set;

public class CookieSetSecure extends Recipe {

    @Override
    public String getDisplayName() {
        return "Insecure cookies";
    }

    @Override
    public String getDescription() {
        return """
               Check for use of insecure cookies. Cookies should be marked as secure. \
               This ensures that the cookie is sent only over HTTPS to prevent cross-site scripting attacks.\
               """;
    }

    @Override
    public Set<String> getTags() {
        return Collections.singleton("CWE-614");
    }

    @Override
    public TreeVisitor<?, ExecutionContext> getVisitor() {
        MethodMatcher newCookie = new MethodMatcher("javax.servlet.http.Cookie <constructor>(..)");
        MethodMatcher setSecure = new MethodMatcher("javax.servlet.http.Cookie setSecure(boolean)");

        return Preconditions.check(new UsesMethod<>(newCookie), new JavaIsoVisitor<ExecutionContext>() {

            @Override
            public J.Block visitBlock(J.Block block, ExecutionContext ctx) {
                J.Block b = super.visitBlock(block, ctx);
                J.VariableDeclarations insecure = getCursor().getMessage("insecure");
                if (insecure != null) {
                    J.MethodInvocation setSecureFalse = getCursor().getMessage("setSecureFalse");
                    if (setSecureFalse == null) {
                        return JavaTemplate.builder("#{any(javax.servlet.http.Cookie)}.setSecure(true);")
                                .javaParser(JavaParser.fromJavaVersion().classpathFromResources(ctx, "javaee-api"))
                                .build()
                                .apply(getCursor(), insecure.getCoordinates().after(),
                                        insecure.getVariables().getFirst().getName());
                    } else {
                        return JavaTemplate.builder("true").build()
                                .apply(getCursor(), setSecureFalse.getCoordinates().replaceArguments());
                    }
                }
                return b;
            }

            @Override
            public J.NewClass visitNewClass(J.NewClass newClass, ExecutionContext ctx) {
                // Currently the rest of this recipe doesn't handle arrays or collections of cookies
                // Return early to avoid making incorrect changes in the absence of enhancements that would enable collections
                J.NewArray newArray = getCursor().firstEnclosing(J.NewArray.class);
                if(newArray != null) {
                    return newClass;
                }
                if (newCookie.matches(newClass) && getCursor().firstEnclosing(J.VariableDeclarations.class) != null) {
                    boolean isInsecure = Dataflow.startingAt(getCursor()).findSinks(new DataFlowSpec() {
                                @Override
                                public boolean isSource(DataFlowNode srcNode) {
                                    return true;
                                }

                                @Override
                                public boolean isSink(DataFlowNode sinkNode) {
                                    Object value = sinkNode.getCursor().getParentTreeCursor().getValue();
                                    return value instanceof J.MethodInvocation mi &&
                                           setSecure.matches(mi);
                                }
                            }).bind(sinkFlow -> {
                                for (Cursor sink : sinkFlow.getSinkCursors()) {
                                    J.MethodInvocation setSecure = sink.getParentTreeCursor().getValue();
                                    Expression arg = setSecure.getArguments().getFirst();
                                    if (!(arg instanceof J.Literal) || Boolean.TRUE.equals(((J.Literal) arg).getValue())) {
                                        // explicitly setSecure(true)
                                        return Option.some(sinkFlow);
                                    }
                                    getCursor().putMessageOnFirstEnclosing(J.Block.class, "setSecureFalse", setSecure);
                                }
                                return Option.none();
                            })
                            .isNone();

                    if (isInsecure) {
                        // either no setSecure call at all, or setSecure(false)
                        getCursor().putMessageOnFirstEnclosing(J.Block.class, "insecure",
                                getCursor().firstEnclosingOrThrow(J.VariableDeclarations.class));
                    }
                }

                return super.visitNewClass(newClass, ctx);
            }
        });
    }
}
