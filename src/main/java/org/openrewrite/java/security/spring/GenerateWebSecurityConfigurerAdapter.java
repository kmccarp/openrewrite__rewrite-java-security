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

import lombok.RequiredArgsConstructor;
import org.openrewrite.ExecutionContext;
import org.openrewrite.Parser;
import org.openrewrite.SourceFile;
import org.openrewrite.java.JavaParser;
import org.openrewrite.java.JavaVisitor;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.format.AutoFormatVisitor;
import org.openrewrite.java.tree.*;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import static java.util.Collections.singletonList;
import static org.openrewrite.Tree.randomId;

@RequiredArgsConstructor
public class GenerateWebSecurityConfigurerAdapter {
    static final String WEB_SECURITY_CONFIGURER_ADAPTER = "org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter";
    static final MethodMatcher CONFIGURE = new MethodMatcher(WEB_SECURITY_CONFIGURER_ADAPTER + " configure(org.springframework.security.config.annotation.web.builders.HttpSecurity)", true);

    private final boolean onlyIfExistingConfig;
    private final JavaVisitor<ExecutionContext> onConfigureBlock;

    List<J.CompilationUnit> springBootApplications = new ArrayList<>();
    Path configurationSourcePath;

    void scan(SourceFile sourceFile, ExecutionContext ctx) {
        if (sourceFile instanceof J.CompilationUnit cu) {
            for (JavaType javaType : cu.getTypesInUse().getTypesInUse()) {
                if (TypeUtils.isOfClassType(javaType, "org.springframework.boot.autoconfigure.SpringBootApplication")) {
                    springBootApplications.add(cu);
                }
            }

            if (configurationSourcePath == null) {
                for (JavaType.Method declaredMethod : cu.getTypesInUse().getDeclaredMethods()) {
                    if (CONFIGURE.matches(declaredMethod)) {
                        configurationSourcePath = cu.getSourcePath();
                    }
                }
            }
        }
    }

    Collection<? extends SourceFile> generate(ExecutionContext ctx) {
        if (configurationSourcePath != null || onlyIfExistingConfig || springBootApplications.isEmpty()) {
            return Collections.emptyList();
        }

        List<J.CompilationUnit> results = new ArrayList<>();
        for (J.CompilationUnit springBootApplication : springBootApplications) {
            J.CompilationUnit generated = JavaParser.fromJavaVersion()
                    .classpathFromResources(ctx, "spring-security-config", "spring-context", "jakarta.servlet-api")
                    .build()
                    .parseInputs(singletonList(new Parser.Input(
                            (springBootApplication.getSourcePath().getParent() == null ? Paths.get("") :
                                    springBootApplication.getSourcePath().getParent())
                                    .resolve("SecurityConfig.java")
                                    .normalize(),
                            () -> GenerateWebSecurityConfigurerAdapter.class
                                    .getResourceAsStream("/WebSecurityConfigurerAdapterTemplate.java")
                    )), null, ctx)
                    .map(J.CompilationUnit.class::cast)
                    .findAny()
                    .get();

            J.Package pkg = springBootApplication.getPackageDeclaration();
            if (pkg != null) {
                generated = generated
                        .withPackageDeclaration(pkg.withId(randomId()))
                        .withPrefix(Space.EMPTY);
            }

            generated = generated.withMarkers(springBootApplication.getMarkers());
            generated = (J.CompilationUnit) new AutoFormatVisitor<ExecutionContext>().visitNonNull(generated, ctx);
            generated = visitConfigureMethod(generated, ctx, onConfigureBlock);
            results.add(generated);
        }

        return results;
    }

    JavaSourceFile modify(JavaSourceFile sourceFile, ExecutionContext ctx) {
        if (sourceFile instanceof J.CompilationUnit cu && sourceFile.getSourcePath().equals(configurationSourcePath)) {
            for (JavaType.Method declaredMethod : cu.getTypesInUse().getDeclaredMethods()) {
                if (CONFIGURE.matches(declaredMethod)) {
                    return visitConfigureMethod(cu, ctx, onConfigureBlock);
                }
            }
        }
        return sourceFile;
    }

    private static J.CompilationUnit visitConfigureMethod(J.CompilationUnit cu, ExecutionContext ctx, JavaVisitor<ExecutionContext> onConfigureBlock) {
        return (J.CompilationUnit) new JavaVisitor<ExecutionContext>() {
            @Override
            public J visitMethodDeclaration(J.MethodDeclaration method, ExecutionContext ctx) {
                if (CONFIGURE.matches(method.getMethodType())) {
                    return method.withBody((J.Block) onConfigureBlock.visit(method.getBody(), ctx, getCursor()));
                }
                return method;
            }
        }.visitNonNull(cu, ctx);
    }
}
