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
import org.openrewrite.Preconditions;
import org.openrewrite.Recipe;
import org.openrewrite.TreeVisitor;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.search.UsesMethod;
import org.openrewrite.java.tree.Expression;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaType;
import org.openrewrite.java.tree.TypeUtils;

import java.time.Duration;
import java.util.Collections;
import java.util.Set;

public class SecureRandomPrefersDefaultSeed extends Recipe {

    @Override
    public String getDisplayName() {
        return "SecureRandom seeds are not constant or predictable";
    }

    @Override
    public String getDescription() {
        return "Remove `SecureRandom#setSeed(*)` method invocations having constant or predictable arguments.";
    }

    @Override
    public Set<String> getTags() {
        return Collections.singleton("RSPEC-S4347");
    }

    @Override
    public Duration getEstimatedEffortPerOccurrence() {
        return Duration.ofMinutes(2);
    }

    @Override
    public TreeVisitor<?, ExecutionContext> getVisitor() {
        return Preconditions.check(new UsesMethod<>("java.security.SecureRandom setSeed(..)"), new SecureRandomUseDefaultSeedVisitor());
    }

    private static class SecureRandomUseDefaultSeedVisitor extends JavaIsoVisitor<ExecutionContext> {
        private static final MethodMatcher SET_SEED_MATCHER = new MethodMatcher("java.security.SecureRandom setSeed(..)");
        private static final MethodMatcher SYSTEM_TIME_MATCHER = new MethodMatcher("java.lang.System currentTimeMillis()");
        private static final MethodMatcher SYSTEM_NANO_TIME_MATCHER = new MethodMatcher("java.lang.System nanoTime()");
        private static final MethodMatcher STRING_BYTES_MATCHER = new MethodMatcher("String getBytes()");
        private final JavaType dateType = JavaType.buildType("java.util.Date");

        @Override
        public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, ExecutionContext ctx) {
            J.MethodInvocation mi = super.visitMethodInvocation(method, ctx);
            if (SET_SEED_MATCHER.matches(mi)) {
                boolean isWeakSeed = false;
                for (Expression arg : mi.getArguments()) {
                    if (arg instanceof J.Literal) {
                        isWeakSeed = true;
                    } else if (arg instanceof J.MethodInvocation argMi) {
                        if (SYSTEM_TIME_MATCHER.matches(arg) || SYSTEM_NANO_TIME_MATCHER.matches(argMi)
                                || (STRING_BYTES_MATCHER.matches(argMi) && argMi.getSelect() instanceof J.Literal)) {
                            isWeakSeed = true;
                        } else if (argMi.getMethodType() != null
                                && (TypeUtils.isAssignableTo(dateType, argMi.getMethodType().getDeclaringType()))) {
                            isWeakSeed = true;
                            maybeRemoveImport("java.util.Date");
                        }
                    }
                }
                if (isWeakSeed) {
                    //noinspection ConstantConditions
                    return null;
                }
            }
            return mi;
        }
    }
}
