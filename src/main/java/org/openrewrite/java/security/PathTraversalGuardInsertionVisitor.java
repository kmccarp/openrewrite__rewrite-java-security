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
package org.openrewrite.java.security;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Value;
import org.openrewrite.Cursor;
import org.openrewrite.Incubating;
import org.openrewrite.Tree;
import org.openrewrite.analysis.InvocationMatcher;
import org.openrewrite.analysis.controlflow.Guard;
import org.openrewrite.analysis.dataflow.*;
import org.openrewrite.analysis.trait.expr.Call;
import org.openrewrite.internal.lang.NonNull;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.*;
import org.openrewrite.java.security.internal.CursorUtil;
import org.openrewrite.java.security.internal.FileConstructorFixVisitor;
import org.openrewrite.java.security.internal.StringToFileConstructorVisitor;
import org.openrewrite.java.security.internal.TypeGenerator;
import org.openrewrite.java.tree.*;
import org.openrewrite.marker.Markers;

import java.util.*;
import java.util.function.Function;
import java.util.function.Supplier;

import static java.util.Collections.emptyList;

/**
 * This visitor detects path traversal vulnerabilities and inserts guards to prevent them.
 * <p>
 * Originally written to handle Zip Slip
 */
@AllArgsConstructor
@Incubating(since = "2.4.0")
public class PathTraversalGuardInsertionVisitor<P> extends JavaIsoVisitor<P> {
    private static final String IMPORT_REQUIRED_MESSAGE = "PATH_TRAVERSAL_IMPORT_REQUIRED";
    final InvocationMatcher userInputMatcher;
    final String newVariablePrefix;
    final String exceptionMessage;
    final boolean fixPartialPathTraversal;

    @Override
    public J.CompilationUnit visitCompilationUnit(J.CompilationUnit cu, P p) {
        J.CompilationUnit compilationUnit = super.visitCompilationUnit(cu, p);
        if (compilationUnit != cu) {
            List<String> requiredImports = getCursor().pollMessage(IMPORT_REQUIRED_MESSAGE);
            if (requiredImports != null) {
                requiredImports.forEach(this::maybeAddImport);
            }
        }
        return compilationUnit;
    }

    @Override
    public J.Block visitBlock(J.Block block, P p) {
        if (fixPartialPathTraversal) {
            // Fix partial-path first before attempting to fix path traversal
            J.Block bPartialPathFix =
                    (J.Block) new PartialPathTraversalVulnerability.PartialPathTraversalVulnerabilityVisitor<>()
                            .visitNonNull(block, p, getCursor().getParentOrThrow());
            if (block != bPartialPathFix) {
                return bPartialPathFix;
            }
        }
        // Partial-path fix didn't change the block, so we can continue with fixing partial path
        J.Block b = super.visitBlock(block, p);
        if (b != block) {
            // Sometimes this visitor will need to be run multiple times to complete it's work
            // That's okay, just return the new block, we'll run this visitor again later if needed
            return b;
        }
        J.Block superB = b;
        Set<Expression> userInputExpressions = computeUserInputExpressions();
        // Before running the fix visitor, we want to get all `File` instantiations into
        // a known good state so that we can later manipulate them safely.
        Supplier<FileConstructorFixVisitor<P>> fileConstructorFixVisitorSupplier =
                () -> new FileConstructorFixVisitor<>(userInputExpressions::contains);
        b = (J.Block) fileConstructorFixVisitorSupplier.get()
                .visitNonNull(b, p, getCursor().getParentOrThrow());
        b = (J.Block) new StringToFileConstructorVisitor<>(fileConstructorFixVisitorSupplier)
                .visitNonNull(b, p, getCursor().getParentOrThrow());
        J.Block before = b;
        b = (J.Block) new PathTraversalVisitor<>(newVariablePrefix, exceptionMessage, userInputMatcher)
                .visitNonNull(b, p, getCursor().getParentOrThrow());
        if (before != b) {
            // Only actually make the change if PathTraversalVisitor actually fixes a vulnerability
            // Don't want to create diffs for just the File constructor manipulation
            return b;
        } else {
            return superB;
        }
    }

    /**
     * Compute the set of Expressions that will have been assigned to by user input.
     */
    private Set<Expression> computeUserInputExpressions() {
        return CursorUtil.findOuterExecutableBlock(getCursor()).map(outerExecutable -> outerExecutable.computeMessageIfAbsent("computed-zip-entry-expressions", __ -> {
            Set<Expression> zipEntryExpressions = new HashSet<>();
            new JavaIsoVisitor<Set<Expression>>() {
                @Override
                public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, Set<Expression> zipEntryExpressionsInternal) {
                    Dataflow.startingAt(getCursor()).findSinks(new UserInputToAnyLocalFlowSpec(userInputMatcher)).forEach(sinkFlow ->
                            zipEntryExpressionsInternal.addAll(sinkFlow.getExpressionSinks()));
                    return super.visitMethodInvocation(method, zipEntryExpressionsInternal);
                }
            }.visit(outerExecutable.getValue(), zipEntryExpressions, outerExecutable.getParentOrThrow());
            return zipEntryExpressions;
        })).orElseGet(HashSet::new);
    }


    @AllArgsConstructor
    private static class UserInputToAnyLocalFlowSpec extends DataFlowSpec {
        InvocationMatcher userInputMatcher;

        @Override
        public boolean isSource(DataFlowNode srcNode) {
            return srcNode.asExprParent(Call.class).map(call -> call.matches(userInputMatcher)).orSome(false);
        }

        @Override
        public boolean isSink(DataFlowNode sinkNode) {
            return true;
        }
    }


    @AllArgsConstructor
    private static class UserInputToFileOrPathCreationLocalFlowSpec extends DataFlowSpec {
        private static final InvocationMatcher FILE_CREATE = InvocationMatcher.fromMethodMatcher(
                "java.io.File <constructor>(.., java.lang.String)"
        );
        private static final InvocationMatcher PATH_RESOLVE = InvocationMatcher.fromMethodMatcher(
                "java.nio.file.Path resolve(..)"
        );

        private final InvocationMatcher userInputMatcher;

        @Override
        public boolean isSource(DataFlowNode srcNode) {
            return srcNode.asExprParent(Call.class).map(call -> call.matches(userInputMatcher)).orSome(false);
        }

        @Override
        public boolean isSink(DataFlowNode sinkNode) {
            return FILE_CREATE.advanced().isParameter(sinkNode.getCursor(), 1) ||
                   PATH_RESOLVE.advanced().isFirstParameter(sinkNode.getCursor());
        }
    }

    @AllArgsConstructor
    private static class PathTraversalVisitor<P> extends JavaIsoVisitor<P> {
        private final String newVariablePrefix;
        private final String exceptionMessage;
        private final InvocationMatcher userInputMatcher;

        @Override
        public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, P p) {
            Dataflow.startingAt(getCursor()).findSinks(new UserInputToFileOrPathCreationLocalFlowSpec(userInputMatcher)).forEach(sinkFlow ->
                    doAfterVisit(new TaintedFileOrPathVisitor<>(
                            newVariablePrefix,
                            exceptionMessage,
                            sinkFlow.getExpressionSinks()
                    ))
            );
            return super.visitMethodInvocation(method, p);
        }
    }

    /**
     * Visitor that handles known tainted {@link java.io.File} or {@link java.nio.file.Path}
     * objects that have been tainted by untrusted user input.
     */
    @AllArgsConstructor
    @EqualsAndHashCode(callSuper = false)
    private static class TaintedFileOrPathVisitor<P> extends JavaVisitor<P> {
        private static final String IO_EXCEPTION_FQN = "java.io.IOException";

        private final JavaType ioException = TypeGenerator.generate(IO_EXCEPTION_FQN);

        private final String newVariablePrefix;
        private final String exceptionMessage;

        @EqualsAndHashCode.Include
        private final List<Expression> taintedSinks;

        private void maybeAddImportIOException() {
            getCursor()
                    .dropParentUntil(J.CompilationUnit.class::isInstance)
                    .computeMessageIfAbsent(IMPORT_REQUIRED_MESSAGE, __ -> Collections.singletonList(IO_EXCEPTION_FQN));
        }

        private String runtimeExceptionThrowLine() {
            return "    throw new RuntimeException(\"%s\");%n".formatted(exceptionMessage);
        }

        private String ioExceptionThrowLine() {
            return "    throw new IOException(\"%s\");%n".formatted(exceptionMessage);
        }

        private JavaTemplate noPathTraversalFileTemplate() {
            boolean canSupportIoException = canSupportScopeSupportExceptionOfType(getCursor(), ioException);
            String exceptionLine = canSupportIoException ? ioExceptionThrowLine() : runtimeExceptionThrowLine();
            JavaTemplate.Builder noPathTraversalFileTemplate = JavaTemplate.builder(
                    "if (!#{any(java.io.File)}.toPath().normalize().startsWith(#{any(java.io.File)}.toPath().normalize())) {\n" +
                    exceptionLine +
                    "}").contextSensitive();
            if (canSupportIoException) {
                noPathTraversalFileTemplate.imports(IO_EXCEPTION_FQN);
                maybeAddImportIOException();
            }
            return noPathTraversalFileTemplate.build();
        }

        private JavaTemplate noPathTraversalFileWithStringTemplate() {
            boolean canSupportIoException = canSupportScopeSupportExceptionOfType(getCursor(), ioException);
            String exceptionLine = canSupportIoException ? ioExceptionThrowLine() : runtimeExceptionThrowLine();
            JavaTemplate.Builder noPathTraversalFileWithStringTemplate = JavaTemplate.builder(
                    "if (!#{any(java.io.File)}.toPath().normalize().startsWith(#{any(String)})) {\n" +
                    exceptionLine +
                    "}").contextSensitive();
            if (canSupportIoException) {
                noPathTraversalFileWithStringTemplate.imports(IO_EXCEPTION_FQN);
                maybeAddImportIOException();
            }
            return noPathTraversalFileWithStringTemplate.build();
        }

        private JavaTemplate noPathTraversalPathStartsWithPathTemplate() {
            boolean canSupportIoException = canSupportScopeSupportExceptionOfType(getCursor(), ioException);
            String exceptionLine = canSupportIoException ? ioExceptionThrowLine() : runtimeExceptionThrowLine();
            JavaTemplate.Builder noPathTraversalPathStartsWithPathTemplate = JavaTemplate.builder(
                    "if (!#{any(java.nio.file.Path)}.normalize().startsWith(#{any(java.nio.file.Path)}.normalize())) {\n" +
                    exceptionLine +
                    "}").contextSensitive();
            if (canSupportIoException) {
                noPathTraversalPathStartsWithPathTemplate.imports(IO_EXCEPTION_FQN);
                maybeAddImportIOException();
            }
            return noPathTraversalPathStartsWithPathTemplate.build();
        }

        private boolean canSupportScopeSupportExceptionOfType(Cursor cursor, JavaType exceptionType) {
            return CursorUtil.canSupportScopeSupportExceptionOfType(cursor, exceptionType);
        }

        @Value
        @NonNull
        private static class PathTraversalSimpleInjectGuardInfo {
            static String CURSOR_KEY = "PathTraversalSimpleInjectGuardInfo";
            /**
             * The statement to create the guard after.
             */
            Statement statement;
            /**
             * The parent directory expression to create the guard for.
             */
            Expression parentDir;
            /**
             * The child file created with the user input to create the guard for.
             */
            Expression userInputEntry;
        }

        @Value
        @NonNull
        public static class PathTraversalCreateNewVariableInfo {
            static String CURSOR_KEY = "PathTraversalCreateNewVariableInfo";
            String newVariableName;
            /**
             * The statement to extract the new variable to before.
             */
            Statement statement;
            /**
             * The expression that needs to be extracted to a new variable.
             */
            MethodCall extractToVariable;
        }

        @Override
        public J visitAssignment(J.Assignment assignment, P p) {
            J newAssignment = super.visitAssignment(assignment, p);
            if (assignment != newAssignment) {
                return maybeAutoFormat(assignment, newAssignment, p, getCursor().getParentOrThrow());
            }
            return newAssignment;
        }

        @Override
        public J visitMethodInvocation(J.MethodInvocation method, P p) {
            return visitMethodCall(method, J.MethodInvocation::getSelect)
                    .<J>map(Function.identity())
                    .orElseGet(() -> super.visitMethodInvocation(method, p));
        }

        @Override
        public J visitNewClass(J.NewClass newClass, P p) {
            return visitMethodCall(newClass, n -> n.getArguments().getFirst())
                    .<J>map(Function.identity())
                    .orElseGet(() -> super.visitNewClass(newClass, p));
        }

        private <M extends MethodCall> Optional<J.Identifier> visitMethodCall(M methodCall, Function<M, Expression> parentDirExtractor) {
            if (methodCall.getArguments().stream().anyMatch(taintedSinks::contains)
                && Dataflow.startingAt(getCursor()).findSinks(new FileOrPathCreationToVulnerableUsageLocalFlowSpec()).isSome()) {
                J.Block firstEnclosingBlock = getCursor().firstEnclosingOrThrow(J.Block.class);
                @SuppressWarnings("SuspiciousMethodCalls")
                Statement enclosingStatement = getCursor()
                        .dropParentUntil(value -> firstEnclosingBlock.getStatements().contains(value))
                        .getValue();

                J.VariableDeclarations.NamedVariable enclosingVariable =
                        getCursor().firstEnclosing(J.VariableDeclarations.NamedVariable.class);

                if (enclosingVariable != null && Expression.unwrap(enclosingVariable.getInitializer()) == methodCall) {
                    J.Identifier enclosingVariableIdentifier = enclosingVariable.getName();

                    PathTraversalSimpleInjectGuardInfo pathTraversalSimpleInjectGuardInfo =
                            new PathTraversalSimpleInjectGuardInfo(
                                    enclosingStatement,
                                    parentDirExtractor.apply(methodCall),
                                    enclosingVariableIdentifier
                            );
                    getCursor()
                            .dropParentUntil(J.Block.class::isInstance)
                            .putMessage(
                                    PathTraversalSimpleInjectGuardInfo.CURSOR_KEY,
                                    pathTraversalSimpleInjectGuardInfo
                            );
                } else {
                    String newVariableBaseName;
                    if (isTypePath(methodCall.getType())) {
                        newVariableBaseName = newVariablePrefix + "Path";
                    } else {
                        assert isTypeFile(methodCall.getType()) :
                                "Expected method call to be of type `java.io.File` or `java.nio.file.Path` but was `" + methodCall.getType() + "`";
                        newVariableBaseName = newVariablePrefix + "File";
                    }
                    String newVariableName = VariableNameUtils.generateVariableName(
                            newVariableBaseName,
                            getCursor(),
                            VariableNameUtils.GenerationStrategy.INCREMENT_NUMBER
                    );
                    PathTraversalCreateNewVariableInfo pathTraversalCreateNewVariableInfo =
                            new PathTraversalCreateNewVariableInfo(
                                    newVariableName,
                                    enclosingStatement,
                                    methodCall
                            );
                    getCursor()
                            .dropParentUntil(J.Block.class::isInstance)
                            .putMessage(
                                    PathTraversalCreateNewVariableInfo.CURSOR_KEY,
                                    pathTraversalCreateNewVariableInfo
                            );
                    return Optional.of(new J.Identifier(
                            Tree.randomId(),
                            Space.EMPTY,
                            Markers.EMPTY,
                            emptyList(),
                            newVariableName,
                            methodCall.getType(),
                            null
                    ));
                }
            }
            return Optional.empty();
        }

        @Override
        public J.Block visitBlock(J.Block block, P p) {
            J.Block b = (J.Block) super.visitBlock(block, p);
            PathTraversalCreateNewVariableInfo pathTraversalCreateNewVariableInfo = getCursor().pollMessage(PathTraversalCreateNewVariableInfo.CURSOR_KEY);
            if (pathTraversalCreateNewVariableInfo != null) {
                JavaTemplate newVariableTemplate;
                if (isTypePath(pathTraversalCreateNewVariableInfo.extractToVariable.getType())) {
                    newVariableTemplate = JavaTemplate
                            .builder(
                                    "final Path " + pathTraversalCreateNewVariableInfo.newVariableName + " = #{any(java.nio.file.Path)};"
                            )
                            .contextSensitive()
                            .imports("java.nio.file.Path")
                            .build();
                    maybeAddImport("java.nio.file.Path");
                } else {
                    assert isTypeFile(pathTraversalCreateNewVariableInfo.extractToVariable.getType());
                    newVariableTemplate = JavaTemplate
                            .builder(
                                    "final File " + pathTraversalCreateNewVariableInfo.newVariableName + " = #{any(java.io.File)};"
                            )
                            .contextSensitive()
                            .imports("java.io.File")
                            .build();
                    maybeAddImport("java.io.File");
                }
                return newVariableTemplate.apply(
                        new Cursor(getCursor().getParent(), b),
                        pathTraversalCreateNewVariableInfo.statement.getCoordinates().before(),
                        pathTraversalCreateNewVariableInfo.extractToVariable);
            }
            PathTraversalSimpleInjectGuardInfo zipSlipSimpleInjectGuardInfo = getCursor().pollMessage(PathTraversalSimpleInjectGuardInfo.CURSOR_KEY);
            if (zipSlipSimpleInjectGuardInfo != null) {
                JavaTemplate template;
                if (isTypeFile(zipSlipSimpleInjectGuardInfo.userInputEntry.getType())) {
                    if (isTypeFile(zipSlipSimpleInjectGuardInfo.parentDir.getType())) {
                        template = noPathTraversalFileTemplate();
                    } else {
                        assert TypeUtils.isString(zipSlipSimpleInjectGuardInfo.parentDir.getType());
                        template = noPathTraversalFileWithStringTemplate();
                    }
                } else {
                    assert isTypePath(zipSlipSimpleInjectGuardInfo.userInputEntry.getType());
                    template = noPathTraversalPathStartsWithPathTemplate();
                }
                return template.apply(
                        new Cursor(getCursor().getParent(), b),
                        zipSlipSimpleInjectGuardInfo.statement.getCoordinates().after(),
                        zipSlipSimpleInjectGuardInfo.userInputEntry,
                        zipSlipSimpleInjectGuardInfo.parentDir);
            }
            return b;
        }
    }

    private static class FileOrPathCreationToVulnerableUsageLocalFlowSpec extends TaintFlowSpec {
        private static final MethodMatcher PATH_STARTS_WITH_MATCHER =
                new MethodMatcher("java.nio.file.Path startsWith(..) ");
        private static final MethodMatcher STRING_STARTS_WITH_MATCHER =
                new MethodMatcher("java.lang.String startsWith(..) ");

        @Override
        public boolean isSource(DataFlowNode srcNode) {
            return true;
        }

        @Override
        public boolean isSink(DataFlowNode sinkNode) {
            return ExternalSinkModels.instance().isSinkNode(sinkNode, "create-file");
        }

        @Override
        public boolean isSanitizerGuard(Guard guard, boolean branch) {
            if (branch) {
                return PATH_STARTS_WITH_MATCHER.matches(guard.getExpression()) ||
                       (STRING_STARTS_WITH_MATCHER.matches(guard.getExpression()) &&
                        PartialPathTraversalVulnerability.isSafePartialPathExpression(((J.MethodInvocation) guard.getExpression()).getArguments().getFirst()));
            } else {
                return false;
            }
        }
    }

    private static boolean isTypeFile(@Nullable JavaType type) {
        return TypeUtils.isOfClassType(type, "java.io.File");
    }

    private static boolean isTypePath(@Nullable JavaType type) {
        return TypeUtils.isOfClassType(type, "java.nio.file.Path");
    }
}
