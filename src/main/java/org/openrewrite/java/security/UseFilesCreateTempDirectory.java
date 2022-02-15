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

import org.openrewrite.ExecutionContext;
import org.openrewrite.Recipe;
import org.openrewrite.internal.ListUtils;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.JavaVisitor;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.marker.JavaVersion;
import org.openrewrite.java.search.UsesMethod;
import org.openrewrite.java.tree.*;

import java.time.Duration;
import java.util.*;

public class UseFilesCreateTempDirectory extends Recipe {

    private static final MethodMatcher CREATE_TEMP_FILE_MATCHER = new MethodMatcher("java.io.File createTempFile(..)");

    @Override
    public String getDisplayName() {
        return "Use Files#createTempDirectory";
    }

    @Override
    public String getDescription() {
        return "Use `Files#createTempDirectory` when the sequence `File#createTempFile(..)`->`File#delete()`->`File#mkdir()` is used for creating a temp directory.";
    }

    @Override
    public Set<String> getTags() {
        return Collections.singleton("RSPEC-5445");
    }

    @Override
    public Duration getEstimatedEffortPerOccurrence() {
        return Duration.ofMinutes(10);
    }

    @Override
    protected JavaVisitor<ExecutionContext> getSingleSourceApplicableTest() {
        return new JavaVisitor<ExecutionContext>() {
            @Override
            public J visitJavaSourceFile(JavaSourceFile cu, ExecutionContext executionContext) {
                doAfterVisit(new UsesMethod<>("java.io.File createTempFile(..)"));
                doAfterVisit(new UsesMethod<>("java.io.File mkdir(..)"));
                return cu;
            }
        };
    }

    @Override
    protected UsesFilesCreateTempDirVisitor getVisitor() {
        return new UsesFilesCreateTempDirVisitor();
    }

    private static class UsesFilesCreateTempDirVisitor extends JavaIsoVisitor<ExecutionContext> {
        private static final MethodMatcher DELETE_MATCHER = new MethodMatcher("java.io.File delete()");
        private static final MethodMatcher MKDIR_MATCHER = new MethodMatcher("java.io.File mkdir()");

        @Override
        public JavaSourceFile visitJavaSourceFile(JavaSourceFile cu, ExecutionContext executionContext) {
            Optional<JavaVersion> javaVersion = cu.getMarkers().findFirst(JavaVersion.class);
            if (javaVersion.isPresent() && javaVersion.get().getMajorVersion() < 7) {
                return cu;
            }
            return super.visitJavaSourceFile(cu, executionContext);
        }

        @Override
        public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, ExecutionContext executionContext) {
            J.MethodInvocation mi = super.visitMethodInvocation(method, executionContext);
            if (CREATE_TEMP_FILE_MATCHER.matches(mi)) {
                J.Block block = getCursor().firstEnclosing(J.Block.class);
                if (block != null) {
                    J createFileStatement = null;
                    J firstParent = getCursor().dropParentUntil(J.class::isInstance).getValue();
                    if (firstParent instanceof J.Assignment && ((J.Assignment) firstParent).getVariable() instanceof J.Identifier) {
                        createFileStatement = firstParent;
                    }
                    if (createFileStatement == null && firstParent instanceof J.VariableDeclarations.NamedVariable) {
                        createFileStatement = firstParent;
                    }
                    if (createFileStatement != null) {
                        getCursor().dropParentUntil(J.Block.class::isInstance)
                                .computeMessageIfAbsent("CREATE_FILE_STATEMENT", v -> new ArrayList<J>()).add(createFileStatement);
                    }
                }
            }
            return mi;
        }

        @Override
        public J.Block visitBlock(J.Block block, ExecutionContext executionContext) {
            J.Block bl = super.visitBlock(block, executionContext);
            List<J> createFileStatements = getCursor().pollMessage("CREATE_FILE_STATEMENT");
            if (createFileStatements != null) {
                for (J createFileStatement : createFileStatements) {
                    final Map<String, Statement> stmtMap = new HashMap<>();
                    for (Statement stmt : bl.getStatements()) {
                        J.Identifier createFileIdentifier = getIdent(createFileStatement);
                        if (createFileIdentifier != null) {
                            if (isMatchingCreateFileStatement(createFileStatement, stmt)) {
                                stmtMap.put("create", stmt);
                                stmtMap.put("secureCreate", (Statement) new SecureTempDirectoryCreation().visitNonNull(stmt, executionContext, getCursor()));
                            } else if (isMethodForIdent(createFileIdentifier, DELETE_MATCHER, stmt)) {
                                stmtMap.put("delete", stmt);
                            } else if (isMethodForIdent(createFileIdentifier, MKDIR_MATCHER, stmt)) {
                                stmtMap.put("mkdir", stmt);
                            }
                        }
                    }
                    if (stmtMap.size() == 4) {
                        bl = bl.withStatements(ListUtils.map(bl.getStatements(), stmt -> {
                            if (stmt == stmtMap.get("create")) {
                                return stmtMap.get("secureCreate");
                            } else if (stmt == stmtMap.get("delete") || stmt == stmtMap.get("mkdir")) {
                                return null;
                            }
                            return stmt;
                        }));
                        maybeAddImport("java.nio.file.Files");
                    }
                }
            }
            return bl;
        }


        private boolean isMatchingCreateFileStatement(J createFileStatement, Statement statement) {
            if (createFileStatement.equals(statement)) {
                return true;
            } else if (createFileStatement instanceof J.VariableDeclarations.NamedVariable && statement instanceof J.VariableDeclarations) {
                J.VariableDeclarations varDecls = (J.VariableDeclarations) statement;
                return varDecls.getVariables().size() == 1 && varDecls.getVariables().get(0).equals(createFileStatement);
            }
            return false;
        }

        private boolean isMethodForIdent(J.Identifier ident, MethodMatcher methodMatcher, Statement statement) {
            if (statement instanceof J.MethodInvocation) {
                J.MethodInvocation mi = (J.MethodInvocation) statement;
                if (mi.getSelect() instanceof J.Identifier && methodMatcher.matches(mi)) {
                    J.Identifier sel = (J.Identifier) mi.getSelect();
                    return ident.getSimpleName().equals(sel.getSimpleName())
                            && TypeUtils.isOfClassType(ident.getType(), "java.io.File");
                }
            }
            return false;
        }

        @Nullable
        private J.Identifier getIdent(J createFileStatement) {
            if (createFileStatement instanceof J.Assignment) {
                J.Assignment assignment = (J.Assignment) createFileStatement;
                return (J.Identifier) assignment.getVariable();
            } else if (createFileStatement instanceof J.VariableDeclarations.NamedVariable) {
                J.VariableDeclarations.NamedVariable var = (J.VariableDeclarations.NamedVariable) createFileStatement;
                return var.getName();
            }
            return null;
        }
    }

    private static class SecureTempDirectoryCreation extends JavaIsoVisitor<ExecutionContext> {
        private final JavaTemplate twoArg = JavaTemplate.builder(this::getCursor, "Files.createTempDirectory(#{any(String)} + #{any(String)}).toFile()")
                .imports("java.nio.file.Files")
                .build();

        private final JavaTemplate threeArg = JavaTemplate.builder(this::getCursor, "Files.createTempDirectory(#{any(java.io.File)}.toPath(), #{any(String)} + #{any(String)}).toFile()")
                .imports("java.nio.file.Files")
                .build();

        @Override
        public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, ExecutionContext executionContext) {
            J.MethodInvocation m = method;
            if (CREATE_TEMP_FILE_MATCHER.matches(m)) {
                maybeAddImport("java.nio.file.Files");
                if (m.getArguments().size() == 2) {
                    // File.createTempFile(String prefix, String suffix)
                    m = maybeAutoFormat(m, m.withTemplate(twoArg,
                                    m.getCoordinates().replace(),
                                    m.getArguments().get(0),
                                    m.getArguments().get(1)),
                            executionContext
                    );
                } else if (m.getArguments().size() == 3) {
                    // File.createTempFile(String prefix, String suffix, File dir)
                    m = maybeAutoFormat(m, m.withTemplate(threeArg,
                                    m.getCoordinates().replace(),
                                    m.getArguments().get(2),
                                    m.getArguments().get(0),
                                    m.getArguments().get(1)),
                            executionContext
                    );
                }
            }
            return m;
        }
    }
}
