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

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.openrewrite.*;
import org.openrewrite.analysis.InvocationMatcher;
import org.openrewrite.internal.ListUtils;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.*;
import org.openrewrite.java.marker.JavaVersion;
import org.openrewrite.java.search.UsesMethod;
import org.openrewrite.java.tree.*;
import org.openrewrite.marker.Markers;
import org.openrewrite.staticanalysis.RemoveUnneededAssertion;
import org.openrewrite.staticanalysis.SimplifyCompoundVisitor;
import org.openrewrite.staticanalysis.SimplifyConstantIfBranchExecution;

import java.io.File;
import java.time.Duration;
import java.util.*;

public class UseFilesCreateTempDirectory extends Recipe {

    private static final MethodMatcher CREATE_TEMP_FILE_MATCHER = new MethodMatcher("java.io.File createTempFile(..)");

    @Override
    public String getDisplayName() {
        return "Use `Files#createTempDirectory`";
    }

    @Override
    public String getDescription() {
        return "Use `Files#createTempDirectory` when the sequence `File#createTempFile(..)`->`File#delete()`->`File#mkdir()` is used for creating a temp directory.";
    }

    @Override
    public Set<String> getTags() {
        return new HashSet<>(Arrays.asList("RSPEC-S5445", "CWE-379", "CWE-377"));
    }

    @Override
    public Duration getEstimatedEffortPerOccurrence() {
        return Duration.ofMinutes(10);
    }

    @Override
    public TreeVisitor<?, ExecutionContext> getVisitor() {
        return Preconditions.check(Preconditions.or(
                new UsesMethod<>("java.io.File createTempFile(..)"),
                new UsesMethod<>("java.io.File mkdir(..)"),
                new UsesMethod<>("java.io.File mkdirs(..)")), new UsesFilesCreateTempDirVisitor());
    }

    private static class UsesFilesCreateTempDirVisitor extends JavaIsoVisitor<ExecutionContext> {
        @Override
        public J.CompilationUnit visitCompilationUnit(J.CompilationUnit cu, ExecutionContext ctx) {
            Optional<JavaVersion> javaVersion = cu.getMarkers().findFirst(JavaVersion.class);
            if (javaVersion.isPresent() && javaVersion.get().getMajorVersion() < 7) {
                return cu;
            }
            return super.visitCompilationUnit(cu, ctx);
        }

        @Override
        public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, ExecutionContext ctx) {
            J.MethodInvocation mi = super.visitMethodInvocation(method, ctx);
            if (CREATE_TEMP_FILE_MATCHER.matches(mi)) {
                J.Block block = getCursor().firstEnclosing(J.Block.class);
                if (block != null) {
                    J createFileStatement = null;
                    J firstParent = getCursor().dropParentUntil(J.class::isInstance).getValue();
                    if (firstParent instanceof J.Assignment assignment && assignment.getVariable() instanceof J.Identifier) {
                        createFileStatement = firstParent;
                    }
                    if (createFileStatement == null && firstParent instanceof J.VariableDeclarations.NamedVariable) {
                        createFileStatement = firstParent;
                    }
                    if (createFileStatement != null) {
                        getCursor().dropParentUntil(J.Block.class::isInstance)
                                .computeMessageIfAbsent("CREATE_FILE_STATEMENT", v -> new ArrayList<>()).add(createFileStatement);
                    }
                }
            }
            return mi;
        }

        @NoArgsConstructor
        private static class TempDirHijackingChainStateMachine {
            private enum State {
                /**
                 * The initial state, no calls have been observed.
                 */
                INIT,
                /**
                 * A call to {@link File#createTempFile} has been observed.
                 */
                CREATE,
                /**
                 * A call to {@link File#delete()} has been observed.
                 */
                DELETE,
                /**
                 * A call to {@link File#mkdir()} or {@link File#mkdirs()} has been observed.
                 */
                MKDIR
            }

            private State state = State.INIT;
            private final Map<String, Statement> stmtMap = new HashMap<>(4);

            void stateCreateStatement(Statement insecureCreateStatement, Statement secureCreateStatement) {
                if (state.equals(State.INIT)) {
                    stmtMap.put("create", insecureCreateStatement);
                    stmtMap.put("secureCreate", secureCreateStatement);
                    state = State.CREATE;
                }
            }

            void stateDeleteStatement(Statement deleteStatement) {
                if (state.equals(State.CREATE)) {
                    stmtMap.put("delete", deleteStatement);
                    state = State.DELETE;
                }
            }

            void stateMkdirStatement(Statement mkdirStatement) {
                if (state.equals(State.DELETE)) {
                    stmtMap.put("mkdir", mkdirStatement);
                    state = State.MKDIR;
                }
            }

            /**
             * The variable that we're tracking through the state machine has been reassigned to a different value.
             */
            public void stateVariableReassigned() {
                if (!state.equals(State.MKDIR)) {
                    state = State.INIT;
                }
            }

            boolean isStateMachineSatisfied() {
                return state.equals(State.MKDIR);
            }

            Statement getCreateStatement() {
                assert isStateMachineSatisfied() : "State machine is not in correct 'final' state.";
                return stmtMap.get("create");
            }

            Statement getSecureCreateStatement() {
                assert isStateMachineSatisfied() : "State machine is not in correct 'final' state.";
                return stmtMap.get("secureCreate");
            }

            Statement getDeleteStatement() {
                assert isStateMachineSatisfied() : "State machine is not in correct 'final' state.";
                return stmtMap.get("delete");
            }

            Statement getMkdirStatement() {
                assert isStateMachineSatisfied() : "State machine is not in correct 'final' state.";
                return stmtMap.get("mkdir");
            }
        }

        @AllArgsConstructor
        private static class TempDirHijackingChainFinderVisitor extends JavaIsoVisitor<TempDirHijackingChainStateMachine> {
            private final InvocationMatcher DELETE_MATCHER = InvocationMatcher.fromMethodMatchers(
                    new MethodMatcher("java.io.File delete()"),
                    new MethodMatcher("org.apache.commons.io.FileUtils delete(..)"),
                    new MethodMatcher("org.apache.commons.io.FileUtils forceDelete(..)"),
                    new MethodMatcher("org.apache.commons.io.FileUtils deleteQuietly(..)")
            );

            private final InvocationMatcher MKDIR_OR_MKDIRS_MATCHER = InvocationMatcher.fromMethodMatchers(
                    new MethodMatcher("java.io.File mkdir()"),
                    new MethodMatcher("java.io.File mkdirs()"),
                    new MethodMatcher("org.apache.commons.io.FileUtils mkdirs(..)"),
                    new MethodMatcher("org.apache.commons.io.FileUtils forceMkdir(..)")
            );

            private final J createFileStatement;

            @Override
            public Statement visitStatement(Statement stmt, TempDirHijackingChainStateMachine stateMachine) {
                Statement s = super.visitStatement(stmt, stateMachine);
                J.Identifier createFileIdentifier = getIdent(createFileStatement);
                if (createFileIdentifier != null) {
                    if (isMatchingCreateFileStatement(createFileStatement, stmt)) {
                        stateMachine.stateCreateStatement(
                                stmt,
                                (Statement) new SecureTempDirectoryCreation<>()
                                        .visitNonNull(stmt, stateMachine, getCursor().getParentOrThrow())
                        );
                    } else if (isMethodForIdent(createFileIdentifier, DELETE_MATCHER, stmt)) {
                        stateMachine.stateDeleteStatement(stmt);
                    } else if (isMethodForIdent(createFileIdentifier, MKDIR_OR_MKDIRS_MATCHER, stmt)) {
                        stateMachine.stateMkdirStatement(stmt);
                    } else if (isAssignmentForIdent(createFileIdentifier, stmt)) {
                        stateMachine.stateVariableReassigned();
                    }
                }
                return s;
            }
        }

        private static class ReplaceStatement<P> extends JavaVisitor<P> {
            private final Statement statement;
            private final Expression replacement;

            public ReplaceStatement(Statement statement, Expression replacement) {
                this.statement = statement;
                this.replacement = replacement;
            }

            @Override
            public J visitExpression(Expression expression, P p) {
                // The statement should only be replaced when removing would cause invalid code.
                if (expression == statement &&
                    // If the direct parent of this expression is a `J.Block` then it should be removed by `DeleteStatementNonIso`.
                    !(getCursor().getParentOrThrow(2).getValue() instanceof J.Block)) {
                    return replacement;
                }
                return super.visitExpression(expression, p);
            }
        }

        private J.Block deleteOrReplaceStatement(J.Block bl, Statement stmt, Expression replacement, ExecutionContext ctx) {
            bl = (J.Block) new DeleteStatement<>(stmt)
                    .visitNonNull(bl, ctx, getCursor().getParentOrThrow());
            bl = (J.Block) new ReplaceStatement<>(
                    stmt,
                    replacement
            ).visitNonNull(bl, ctx, getCursor().getParentOrThrow());
            return bl;
        }

        @Override
        public J.Block visitBlock(J.Block block, ExecutionContext ctx) {
            J.Block bl = super.visitBlock(block, ctx);
            List<J> createFileStatements = getCursor().pollMessage("CREATE_FILE_STATEMENT");
            if (createFileStatements != null) {
                for (J createFileStatement : createFileStatements) {
                    TempDirHijackingChainStateMachine stateMachine =
                            new TempDirHijackingChainStateMachine();

                    new TempDirHijackingChainFinderVisitor(createFileStatement)
                            .visitNonNull(bl, stateMachine, getCursor().getParentOrThrow());

                    if (stateMachine.isStateMachineSatisfied()) {
                        bl = bl.withStatements(ListUtils.map(bl.getStatements(), stmt -> {
                            if (stmt == stateMachine.getCreateStatement()) {
                                return stateMachine.getSecureCreateStatement();
                            }
                            return stmt;
                        }));
                        maybeAddImport("java.nio.file.Files");
                        Statement delete = stateMachine.getDeleteStatement();
                        bl = deleteOrReplaceStatement(bl, delete, trueLiteral(delete.getPrefix()), ctx);
                        Statement mkdir = stateMachine.getMkdirStatement();
                        bl = deleteOrReplaceStatement(bl, mkdir, trueLiteral(mkdir.getPrefix()), ctx);
                        bl = (J.Block) new SimplifyConstantIfBranchExecution()
                                .getVisitor()
                                .visitNonNull(bl, ctx, getCursor().getParentOrThrow());
                        bl = (J.Block) new SimplifyCompoundVisitor()
                                .visitNonNull(bl, ctx, getCursor().getParentOrThrow());
                        // Remove any silly assertions that may be lingering like `assertTrue(true)`
                        doAfterVisit(new RemoveUnneededAssertion().getVisitor());
                    }
                }
            }
            return bl;
        }

        private static J.Literal trueLiteral(Space prefix) {
            return new J.Literal(
                    Tree.randomId(),
                    prefix,
                    Markers.EMPTY,
                    true,
                    "true",
                    null,
                    JavaType.Primitive.Boolean
            );
        }

        private static boolean isMatchingCreateFileStatement(J createFileStatement, Statement statement) {
            if (createFileStatement.equals(statement)) {
                return true;
            } else if (createFileStatement instanceof J.VariableDeclarations.NamedVariable && statement instanceof J.VariableDeclarations varDecls) {
                return varDecls.getVariables().size() == 1 && varDecls.getVariables().getFirst().equals(createFileStatement);
            }
            return false;
        }

        private static boolean isAssignmentForIdent(J.Identifier ident, Statement statement) {
            if (statement instanceof J.Assignment assignment) {
                Expression variable = assignment.getVariable();
                if (variable instanceof J.Identifier variableIdent) {
                    return ident.getSimpleName().equals(variableIdent.getSimpleName()) &&
                           TypeUtils.isOfClassType(variableIdent.getType(), "java.io.File");
                }
            }
            return false;
        }

        private static boolean isMethodForIdent(J.Identifier ident, InvocationMatcher invocationMatcher, Statement statement) {
            if (!TypeUtils.isOfClassType(ident.getType(), "java.io.File")) {
                return false;
            }
            if (statement instanceof J.MethodInvocation mi) {
                if (!invocationMatcher.matches(mi)) {
                    return false;
                }
                J.Identifier sel;
                if (mi.getSelect() != null && mi.getSelect().unwrap() instanceof J.Identifier) {
                    sel = (J.Identifier) mi.getSelect().unwrap();
                } else if (!mi.getArguments().isEmpty() && mi.getArguments().getFirst().unwrap() instanceof J.Identifier) {
                    sel = (J.Identifier) mi.getArguments().getFirst().unwrap();
                } else {
                    return false;
                }
                return ident.getSimpleName().equals(sel.getSimpleName());
            }
            return false;
        }

        @Nullable
        private static J.Identifier getIdent(J createFileStatement) {
            if (createFileStatement instanceof J.Assignment assignment) {
                return (J.Identifier) assignment.getVariable();
            } else if (createFileStatement instanceof J.VariableDeclarations.NamedVariable var) {
                return var.getName();
            }
            return null;
        }
    }

    private static class SecureTempDirectoryCreation<P> extends JavaIsoVisitor<P> {
        private final JavaTemplate twoArg = JavaTemplate.builder("Files.createTempDirectory(#{any(String)} + #{any(String)}).toFile()")
                .imports("java.nio.file.Files")
                .build();

        private final JavaTemplate threeArg = JavaTemplate.builder("Files.createTempDirectory(#{any(java.io.File)}.toPath(), #{any(String)} + #{any(String)}).toFile()")
                .imports("java.nio.file.Files")
                .build();

        @Override
        public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, P p) {
            J.MethodInvocation m = method;
            if (CREATE_TEMP_FILE_MATCHER.matches(m)) {
                if (m.getArguments().size() == 2
                    || (m.getArguments().size() == 3 && m.getArguments().get(2).getType() == JavaType.Primitive.Null)) {
                    // File.createTempFile(String prefix, String suffix)
                    m = maybeAutoFormat(m, twoArg.apply(
                                    getCursor(),
                                    m.getCoordinates().replace(),
                                    m.getArguments().getFirst(),
                                    m.getArguments().get(1)),
                            p
                    );
                } else if (m.getArguments().size() == 3) {
                    // File.createTempFile(String prefix, String suffix, File dir)
                    m = maybeAutoFormat(m, threeArg.apply(
                                    getCursor(),
                                    m.getCoordinates().replace(),
                                    m.getArguments().get(2),
                                    m.getArguments().getFirst(),
                                    m.getArguments().get(1)),
                            p
                    );
                }
                J.MethodInvocation select = (J.MethodInvocation) m.getSelect();
                //noinspection ConstantConditions
                select = select.withArguments(ListUtils.map(select.getArguments(), arg -> {
                    if (arg instanceof J.Binary binaryArg) {
                        Expression rightArg = binaryArg.getRight();
                        if (rightArg.getType() == JavaType.Primitive.Null) {
                            return binaryArg.getLeft();
                        } else if (rightArg instanceof J.Literal literalRight) {
                            if (literalRight.getValueSource() != null && "\"\"".equals(literalRight.getValueSource())) {
                                return binaryArg.getLeft();
                            }
                        }
                    }
                    return arg;
                }));
                m = maybeAutoFormat(m, m.withSelect(select), p);
                maybeAddImport("java.nio.file.Files");
                maybeRemoveImport("java.io.File");
            }
            return m;
        }
    }
}
