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
package org.openrewrite.java.security.internal;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.openrewrite.Cursor;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaType;
import org.openrewrite.java.tree.TypeUtils;

import java.util.Iterator;
import java.util.Optional;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class CursorUtil {
    /**
     * Find the outermost executable {@link J.Block} that is an executable set of instructions.
     * This is one of the following:
     * <ul>
     *     <li>A {@link J.Block} that is either static or an init block.</li>
     *     <li>The block held by a {@link J.MethodInvocation}.</li>
     * </ul>
     */
    public static Optional<Cursor> findOuterExecutableBlock(Cursor start) {
        Iterator<Cursor> path = start.getPathAsCursors();
        Cursor parent = path.next();
        while (path.hasNext()) {
            Cursor cursor = path.next();
            if (cursor.getValue() instanceof J.MethodDeclaration) {
                assert parent.getValue() instanceof J.Block : "Parent of method declaration is not a block. Was: " + parent.getValue();
                return Optional.of(parent);
            }
            if (cursor.getValue() instanceof J.Block && J.Block.isStaticOrInitBlock(cursor)) {
                return Optional.of(cursor);
            }
            parent = cursor;
        }
        return Optional.empty();
    }

    public static boolean canSupportScopeSupportExceptionOfType(Cursor cursor, JavaType exceptionType) {
        Iterator<Cursor> cursors =
                cursor.getPathAsCursors(
                        c -> isStaticOrInitBlockSafe(c) ||
                             c.getValue() instanceof J.MethodDeclaration ||
                             c.getValue() instanceof J.Try
                );
        while (cursors.hasNext()) {
            Cursor c = cursors.next();
            if (isStaticOrInitBlockSafe(c)) {
                return false;
            } else if (c.getValue() instanceof J.Try) {
                J.Try tryBlock = c.getValue();
                if (tryBlock.getCatches().stream().anyMatch(catchClause ->
                        catchClause.getParameter().getTree().getVariables().stream().anyMatch(v ->
                                TypeUtils.isAssignableTo(v.getType(), exceptionType)))) {
                    return true;
                }
            } else if (c.getValue() instanceof J.MethodDeclaration) {
                J.MethodDeclaration methodDeclaration = c.getValue();
                if (methodDeclaration.getThrows() != null &&
                    methodDeclaration.getThrows().stream().anyMatch(throwsClause ->
                            TypeUtils.isAssignableTo(throwsClause.getType(), exceptionType))) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean isStaticOrInitBlockSafe(Cursor cursor) {
        return cursor.getValue() instanceof J.Block && J.Block.isStaticOrInitBlock(cursor);
    }
}
