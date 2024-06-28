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

import io.micrometer.core.lang.Nullable;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.openrewrite.java.tree.Expression;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaType;
import org.openrewrite.java.tree.TypeUtils;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class FileSeparatorUtil {

    public static boolean isFileSeparatorExpression(@Nullable Expression e) {
        Expression expression = Expression.unwrap(e);
        if (expression instanceof J.FieldAccess || expression instanceof J.Identifier) {
            // CASE:
            // - File.separator
            // - File.separatorChar
            // - separator
            // - separatorChar
            J.Identifier nameIdentifier;
            JavaType type;
            if (expression instanceof J.FieldAccess access) {
                // CASE:
                // - File.separator
                // - File.separatorChar
                nameIdentifier = access.getName();
                type = access.getTarget().getType();
            } else {
                // CASE:
                // - separator statically imported from java.io.File
                // - separatorChar statically imported from java.io.File
                if (((J.Identifier) expression).getFieldType() == null) {
                    return false;
                }
                nameIdentifier = (J.Identifier) expression;
                type = ((J.Identifier) expression).getFieldType().getOwner();
            }
            String name = nameIdentifier.getSimpleName();
            return ("separator".equals(name) || "separatorChar".equals(name)) &&
                    TypeUtils.isOfClassType(type, "java.io.File");
        } else if (expression instanceof J.Literal literal) {
            if (literal.getValue() instanceof String) {
                String value = (String) literal.getValue();
                // CASE:
                // - "/"
                // - "\\"
                return "/".equals(value) || "\\".equals(value);
            } else if (literal.getValue() instanceof Character) {
                Character value = (Character) literal.getValue();
                // CASE:
                // - '/'
                // - '\'
                return value.equals('/') || value.equals('\\');
            }
        }
        return false;
    }
}
