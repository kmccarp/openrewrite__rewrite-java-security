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
package org.openrewrite.java.security.spring;

import lombok.EqualsAndHashCode;
import lombok.Value;
import org.openrewrite.*;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.*;
import org.openrewrite.java.search.HasTypeOnClasspathSourceSet;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaSourceFile;
import org.openrewrite.java.tree.JavaType;

import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import static org.openrewrite.java.security.spring.GenerateWebSecurityConfigurerAdapter.WEB_SECURITY_CONFIGURER_ADAPTER;

@Value
@EqualsAndHashCode(callSuper = false)
public class PreventClickjacking extends ScanningRecipe<GenerateWebSecurityConfigurerAdapter> {

    @Option(displayName = "Only if security configuration exists",
            description = "Only patch existing implementations of `WebSecurityConfigurerAdapter`.",
            required = false)
    @Nullable
    Boolean onlyIfSecurityConfig;

    @Override
    public String getDisplayName() {
        return "Prevent clickjacking";
    }

    @Override
    public String getDescription() {
        return "The `frame-ancestors` directive can be used in a Content-Security-Policy HTTP response header to indicate whether or not a browser should be allowed to render a page in a `<frame>` or `<iframe>`. Sites can use this to avoid Clickjacking attacks by ensuring that their content is not embedded into other sites.";
    }

    @Override
    public Set<String> getTags() {
        return Collections.singleton("CWE-1021");
    }

    @Override
    public Duration getEstimatedEffortPerOccurrence() {
        return Duration.ofMinutes(10);
    }

    private static final MethodMatcher FRAME_OPTIONS = new MethodMatcher("org.springframework.security.config.annotation.web.configurers.HeadersConfigurer frameOptions()");

    @Override
    public GenerateWebSecurityConfigurerAdapter getInitialValue(ExecutionContext ctx) {
        return new GenerateWebSecurityConfigurerAdapter(Boolean.TRUE.equals(onlyIfSecurityConfig), new JavaVisitor<ExecutionContext>() {
            @Override
            public J visitBlock(J.Block block, ExecutionContext ctx) {
                for (JavaType.Method method : getCursor().firstEnclosingOrThrow(JavaSourceFile.class).getTypesInUse().getUsedMethods()) {
                    if (FRAME_OPTIONS.matches(method)) {
                        return block;
                    }
                }
                return JavaTemplate
                        .builder("http.headers().frameOptions().deny();")
                        .contextSensitive()
                        .javaParser(JavaParser.fromJavaVersion()
                                .classpathFromResources(ctx, "spring-security-config", "spring-context", "jakarta.servlet-api"))
                        .build()
                        .apply(getCursor(), block.getCoordinates().lastStatement());
            }
        });
    }

    @Override
    public TreeVisitor<?, ExecutionContext> getScanner(GenerateWebSecurityConfigurerAdapter acc) {
        return new TreeVisitor<Tree, ExecutionContext>() {
            @Override
            public @Nullable Tree visit(@Nullable Tree tree, ExecutionContext ctx) {
                if (tree instanceof SourceFile file) {
                    acc.scan(file, ctx);
                }
                return tree;
            }
        };
    }

    @Override
    public Collection<? extends SourceFile> generate(GenerateWebSecurityConfigurerAdapter acc, ExecutionContext ctx) {
        return acc.generate(ctx);
    }

    @Override
    public TreeVisitor<?, ExecutionContext> getVisitor(GenerateWebSecurityConfigurerAdapter acc) {
        return Preconditions.check(new HasTypeOnClasspathSourceSet<>(WEB_SECURITY_CONFIGURER_ADAPTER), new TreeVisitor<Tree, ExecutionContext>() {
            @Override
            public Tree preVisit(Tree tree, ExecutionContext ctx) {
                stopAfterPreVisit();
                if (tree instanceof JavaSourceFile file) {
                    return acc.modify(file, ctx);
                }
                return tree;
            }
        });
    }

}
