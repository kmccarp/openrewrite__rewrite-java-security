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
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaSourceFile;
import org.openrewrite.java.tree.JavaType;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

@Value
@EqualsAndHashCode(callSuper = false)
public class CsrfProtection extends ScanningRecipe<GenerateWebSecurityConfigurerAdapter> {

    @Option(displayName = "Only if security configuration exists",
            description = "Only patch existing implementations of `WebSecurityConfigurerAdapter`.",
            required = false)
    @Nullable
    Boolean onlyIfSecurityConfig;

    @Override
    public String getDisplayName() {
        return "Enable CSRF attack prevention";
    }

    @Override
    public String getDescription() {
        return "Cross-Site Request Forgery (CSRF) is a type of attack that occurs when a malicious web site, email, blog, instant message, or program causes a user's web browser to perform an unwanted action on a trusted site when the user is authenticated. See the full [OWASP cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).";
    }

    @Override
    public Set<String> getTags() {
        return Collections.singleton("CWE-352");
    }

    static final MethodMatcher CSRF = new MethodMatcher("org.springframework.security.config.annotation.web.builders.HttpSecurity csrf()");

    @Override
    public GenerateWebSecurityConfigurerAdapter getInitialValue(ExecutionContext ctx) {
        return new GenerateWebSecurityConfigurerAdapter(Boolean.TRUE.equals(onlyIfSecurityConfig), new JavaVisitor<ExecutionContext>() {
            @Override
            public J visitBlock(J.Block block, ExecutionContext ctx) {
                for (JavaType.Method method : getCursor().firstEnclosingOrThrow(JavaSourceFile.class).getTypesInUse().getUsedMethods()) {
                    if (CSRF.matches(method)) {
                        return block;
                    }
                }

                return JavaTemplate
                        .builder("""
                                 http\
                                 .csrf()\
                                 .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());\
                                 """)
                        .contextSensitive()
                        .imports("org.springframework.security.web.csrf.CookieCsrfTokenRepository")
                        .javaParser(JavaParser.fromJavaVersion()
                                .classpathFromResources(ctx,
                                        "spring-security-config",
                                        "spring-context",
                                        "jakarta.servlet-api",
                                        "spring-security-web"
                                ))
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
        return new JavaIsoVisitor<ExecutionContext>() {
            @Override
            public J preVisit(J tree, ExecutionContext ctx) {
                stopAfterPreVisit();
                if (tree instanceof JavaSourceFile file) {
                    maybeAddImport("org.springframework.security.web.csrf.CookieCsrfTokenRepository");
                    return acc.modify(file, ctx);
                }
                return tree;
            }
        };
    }
}
