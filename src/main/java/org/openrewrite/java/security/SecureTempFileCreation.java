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

import lombok.EqualsAndHashCode;
import lombok.Value;
import org.openrewrite.ExecutionContext;
import org.openrewrite.Preconditions;
import org.openrewrite.Recipe;
import org.openrewrite.TreeVisitor;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.search.UsesMethod;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaType;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Set;


@Value
@EqualsAndHashCode(callSuper = false)
public class SecureTempFileCreation extends Recipe {

    @Override
    public String getDisplayName() {
        return "Use secure temporary file creation";
    }

    @Override
    public String getDescription() {
        return "`java.io.File.createTempFile()` has exploitable default file permissions. This recipe migrates to the more secure `java.nio.file.Files.createTempFile()`.";
    }

    @Override
    public @Nullable Duration getEstimatedEffortPerOccurrence() {
        return Duration.ofMinutes(1);
    }

    @Override
    public Set<String> getTags() {
        return Collections.singleton("CWE-377");
    }

    @Override
    public TreeVisitor<?, ExecutionContext> getVisitor() {
        return Preconditions.check(new UsesMethod<>(SecureTempFileCreationVisitor.MATCHER), new SecureTempFileCreationVisitor());
    }

    static class SecureTempFileCreationVisitor extends JavaIsoVisitor<ExecutionContext> {

        static final MethodMatcher MATCHER = new MethodMatcher("java.io.File createTempFile(..)");
        private final JavaTemplate twoArg = JavaTemplate.builder("Files.createTempFile(#{any(String)}, #{any(String)}).toFile()")
                .imports("java.nio.file.Files")
                .build();

        private final JavaTemplate threeArg = JavaTemplate.builder("Files.createTempFile(#{any(java.io.File)}.toPath(), #{any(String)}, #{any(String)}).toFile()")
                .imports("java.nio.file.Files")
                .build();

        @Override
        public void visit(@Nullable List<? extends J> nodes, ExecutionContext ctx) {
            super.visit(nodes, ctx);
        }

        @Override
        public J.Block visitBlock(J.Block block, ExecutionContext ctx) {
            J.Block createTempDirectoryFix = (J.Block) new UseFilesCreateTempDirectory()
                    .getVisitor()
                    .visitNonNull(block, ctx, getCursor().getParentOrThrow());
            if (createTempDirectoryFix != block) {
                // If the issue could be fixed by the UseFilesCreateTempDirectory's visitor
                // then this visitor should not be applied.
                return block;
            } else {
                return super.visitBlock(block, ctx);
            }
        }

        @Override
        public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, ExecutionContext ctx) {
            J.MethodInvocation m = method;
            if (MATCHER.matches(m)) {
                maybeAddImport("java.nio.file.Files");
                if (m.getArguments().size() == 2 || (m.getArguments().size() == 3 && m.getArguments().get(2).getType() == JavaType.Primitive.Null)) {
                    // File.createTempFile(String prefix, String suffix)
                    m = twoArg.apply(
                            getCursor(),
                            m.getCoordinates().replace(),
                            m.getArguments().getFirst(),
                            m.getArguments().get(1)
                    );
                } else if (m.getArguments().size() == 3) {
                    // File.createTempFile(String prefix, String suffix, File dir)
                    m = threeArg.apply(
                            getCursor(),
                            m.getCoordinates().replace(),
                            m.getArguments().get(2),
                            m.getArguments().getFirst(),
                            m.getArguments().get(1)
                    );
                }
            }
            return m;
        }
    }
}
