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

import org.openrewrite.Cursor;
import org.openrewrite.ExecutionContext;
import org.openrewrite.Recipe;
import org.openrewrite.TreeVisitor;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.*;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaType;
import org.openrewrite.java.tree.TypeUtils;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.Stack;
import java.util.concurrent.atomic.AtomicBoolean;

public class SecureSnakeYamlConstructor extends Recipe {
    private static final MethodMatcher snakeYamlZeroArgumentConstructor = new MethodMatcher("org.yaml.snakeyaml.Yaml <constructor>()", true);
    private static final MethodMatcher snakeYamlRepresenterArgumentConstructor = new MethodMatcher("org.yaml.snakeyaml.Yaml <constructor>(org.yaml.snakeyaml.representer.Representer)", true);
    private static final MethodMatcher snakeYamlDumperArgumentConstructor = new MethodMatcher("org.yaml.snakeyaml.Yaml <constructor>(org.yaml.snakeyaml.DumperOptions)", true);

    @Override
    public String getDisplayName() {
        return "Secure the use of SnakeYAML's constructor";
    }

    @Override
    public String getDescription() {
        return "See the [paper](https://github.com/mbechler/marshalsec) on this subject.";
    }

    @Override
    public Set<String> getTags() {
        return new HashSet<>(Arrays.asList("CWE-502", "CWE-94"));
    }

    @Override
    public TreeVisitor<?, ExecutionContext> getVisitor() {
        return new JavaVisitor<ExecutionContext>() {
            @Override
            public J visitMemberReference(J.MemberReference memberRef, ExecutionContext ctx) {
                if (snakeYamlZeroArgumentConstructor.matches(memberRef.getMethodType())) {
                    maybeAddImport("org.yaml.snakeyaml.constructor.SafeConstructor");
                    return JavaTemplate
                            .builder("() -> new Yaml(new SafeConstructor())")
                            .imports("org.yaml.snakeyaml.Yaml")
                            .imports("org.yaml.snakeyaml.constructor.SafeConstructor")
                            .javaParser(JavaParser.fromJavaVersion()
                                    .classpathFromResources(ctx, "snakeyaml-1.33"))
                            .build()
                            .apply(getCursor(), memberRef.getCoordinates().replace());
                }
                return super.visitMemberReference(memberRef, ctx);
            }

            @Override
            public J visitNewClass(J.NewClass newClass, ExecutionContext ctx) {
                Cursor outerExecutableBlockCursor = getOuterMostExecutableBlock(getCursor());
                if (outerExecutableBlockCursor != null && !isSnakeYamlUsedUnsafeOrEscapesScope(outerExecutableBlockCursor)) {
                    return newClass;
                }
                if (snakeYamlZeroArgumentConstructor.matches(newClass)) {
                    JavaType.Method ctorType = newClass.getConstructorType();
                    assert ctorType != null;

                    maybeAddImport("org.yaml.snakeyaml.constructor.SafeConstructor");
                    return JavaTemplate
                            .builder("new Yaml(new SafeConstructor())")
                            .imports("org.yaml.snakeyaml.Yaml")
                            .imports("org.yaml.snakeyaml.constructor.SafeConstructor")
                            .javaParser(JavaParser.fromJavaVersion()
                                    .classpathFromResources(ctx, "snakeyaml-1.33"))
                            .build()
                            .apply(getCursor(), newClass.getCoordinates().replace());
                } else if (snakeYamlRepresenterArgumentConstructor.matches(newClass)) {
                    JavaType.Method ctorType = newClass.getConstructorType();
                    assert ctorType != null;

                    maybeAddImport("org.yaml.snakeyaml.constructor.SafeConstructor");
                    maybeAddImport("org.yaml.snakeyaml.DumperOptions");
                    return JavaTemplate
                            .builder("new Yaml(new SafeConstructor(), #{any(org.yaml.snakeyaml.representer.Representer)}, new DumperOptions())")
                            .imports(
                                    "org.yaml.snakeyaml.Yaml",
                                    "org.yaml.snakeyaml.DumperOptions",
                                    "org.yaml.snakeyaml.constructor.SafeConstructor",
                                    "org.yaml.snakeyaml.representer.Representer"
                            )
                            .javaParser(JavaParser.fromJavaVersion()
                                    .classpathFromResources(ctx, "snakeyaml-1.33"))
                            .build()
                            .apply(getCursor(), newClass.getCoordinates().replace(), newClass.getArguments().getFirst());
                } else if (snakeYamlDumperArgumentConstructor.matches(newClass)) {
                    JavaType.Method ctorType = newClass.getConstructorType();
                    assert ctorType != null;

                    maybeAddImport("org.yaml.snakeyaml.constructor.SafeConstructor");
                    maybeAddImport("org.yaml.snakeyaml.representer.Representer");
                    return JavaTemplate
                            .builder("new Yaml(new SafeConstructor(), new Representer(), #{any(org.yaml.snakeyaml.DumperOptions)})")
                            .imports(
                                    "org.yaml.snakeyaml.Yaml",
                                    "org.yaml.snakeyaml.DumperOptions",
                                    "org.yaml.snakeyaml.constructor.SafeConstructor",
                                    "org.yaml.snakeyaml.representer.Representer"
                            )
                            .javaParser(JavaParser.fromJavaVersion()
                                    .classpathFromResources(ctx, "snakeyaml-1.33"))
                            .build()
                            .apply(getCursor(), newClass.getCoordinates().replace(), newClass.getArguments().getFirst());
                }

                return super.visitNewClass(newClass, ctx);
            }
        };
    }

    /**
     * The {@link J.Block} that is passed should either be an init block, static block, or the body of a method.
     *
     * @return true if some instance of a <code>Yaml</code> class is created in the block, and that instance is used in an unsafe way,
     * or if it 'escapes' the scope of the block by being assigned to a variable outside the scope, passed as an argument, or returned.
     */
    private static boolean isSnakeYamlUsedUnsafeOrEscapesScope(Cursor scope) {
        J.Block block = scope.getValue();

        // The method arguments, if any are present. Not relevant in the scope of a static or init block.
        Set<String> methodArguments = new HashSet<>();
        Cursor maybeMethodDeclaration = scope.getParentOrThrow();
        if (maybeMethodDeclaration.getValue() instanceof J.MethodDeclaration) {
            J.MethodDeclaration methodDeclaration = maybeMethodDeclaration.getValue();
            methodDeclaration
                    .getParameters()
                    .stream()
                    .filter(org.openrewrite.java.tree.J.VariableDeclarations.class::isInstance)
                    .flatMap(p -> ((J.VariableDeclarations) p).getVariables().stream())
                    .forEach(v -> methodArguments.add(v.getSimpleName()));
        }

        AtomicBoolean isUnsafe = new AtomicBoolean(false);
        new JavaIsoVisitor<AtomicBoolean>() {
            final Stack<Set<String>> variablesDeclaredInScope;

            {
                variablesDeclaredInScope = new Stack<>();
                variablesDeclaredInScope.push(methodArguments);
            }

            boolean isVariableInScope(String name) {
                return variablesDeclaredInScope
                        .stream()
                        .flatMap(Set::stream)
                        .anyMatch(name::equals);
            }

            @Override
            public J.Block visitBlock(J.Block block, AtomicBoolean atomicBoolean) {
                // short circuit if we've already determined that the block is unsafe
                if (atomicBoolean.get()) {
                    return block;
                }
                // otherwise, visit the block normally
                // if we find a variable declaration, add it to the set of variables declared in the current scope
                variablesDeclaredInScope.push(new HashSet<>());
                J.Block b = super.visitBlock(block, atomicBoolean);
                // once we've visited the block, remove the set of variables declared in the current scope
                variablesDeclaredInScope.pop();
                return b;
            }

            @Override
            public J.VariableDeclarations.NamedVariable visitVariable(J.VariableDeclarations.NamedVariable variable, AtomicBoolean atomicBoolean) {
                J.VariableDeclarations.NamedVariable v = super.visitVariable(variable, atomicBoolean);
                // add the variable to the set of variables declared in the current scope
                variablesDeclaredInScope.peek().add(v.getSimpleName());
                return v;
            }

            @Override
            public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, AtomicBoolean atomicBoolean) {
                if (method.getSelect() != null &&
                        isSnakeYamlType(method.getSelect().getType()) &&
                        method.getName().getSimpleName().startsWith("load")) {
                    atomicBoolean.set(true);
                    return method;
                }
                if (method.getArguments().stream().anyMatch(arg -> isSnakeYamlType(arg.getType()))) {
                    atomicBoolean.set(true);
                    return method;
                }
                return super.visitMethodInvocation(method, atomicBoolean);
            }

            @Override
            public J.Assignment visitAssignment(J.Assignment assignment, AtomicBoolean atomicBoolean) {
                if (isSnakeYamlType(assignment.getAssignment().getType()) &&
                        (assignment.getVariable() instanceof J.Identifier &&
                                !isVariableInScope(((J.Identifier) assignment.getVariable()).getSimpleName())) ||
                        !(assignment.getVariable() instanceof J.Identifier)) {
                    atomicBoolean.set(true);
                    return assignment;
                }
                return super.visitAssignment(assignment, atomicBoolean);
            }

            @Override
            public J.Return visitReturn(J.Return _return, AtomicBoolean atomicBoolean) {
                if (_return.getExpression() != null && isSnakeYamlType(_return.getExpression().getType())) {
                    atomicBoolean.set(true);
                    return _return;
                }
                return super.visitReturn(_return, atomicBoolean);
            }

            private boolean isSnakeYamlType(@Nullable JavaType type) {
                return TypeUtils.isAssignableTo("org.yaml.snakeyaml.Yaml", type);
            }
        }.visit(block, isUnsafe, scope.getParentOrThrow());
        return isUnsafe.get();
    }

    @Nullable
    private static Cursor getOuterMostExecutableBlock(Cursor startCursor) {
        Cursor blockCursor = null;
        for (Cursor cursor : (Iterable<Cursor>) startCursor::getPathAsCursors) {
            Object cursorValue = cursor.getValue();
            if (cursorValue instanceof J.Block) {
                if (J.Block.isStaticOrInitBlock(cursor)) {
                    return cursor;
                }
                blockCursor = cursor;
            }
            if (cursorValue instanceof J.ClassDeclaration) {
                return null;
            }
            if (cursorValue instanceof J.MethodDeclaration) {
                return blockCursor;
            }
        }
        return null;
    }
}
