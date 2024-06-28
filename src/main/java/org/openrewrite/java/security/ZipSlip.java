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
import org.openrewrite.*;
import org.openrewrite.analysis.InvocationMatcher;
import org.openrewrite.analysis.search.UsesInvocation;
import org.openrewrite.java.MethodMatcher;

import java.time.Duration;
import java.util.Collections;
import java.util.Set;

@Value
@EqualsAndHashCode(callSuper = false)
public class ZipSlip extends Recipe {
    static final InvocationMatcher ZIP_ENTRY_GET_NAME = InvocationMatcher.fromMethodMatchers(
            new MethodMatcher("java.util.zip.ZipEntry getName()", true),
            new MethodMatcher("org.apache.commons.compress.archivers.zip.ZipArchiveEntry getName()", true)
    );

    @Override
    public String getDisplayName() {
        return "Zip slip";
    }

    @Override
    public String getDescription() {
        return """
               Zip slip is an arbitrary file overwrite critical vulnerability, which typically results in remote command execution. \
               A fuller description of this vulnerability is available in the [Snyk documentation](https://snyk.io/research/zip-slip-vulnerability) on it.\
               """;
    }

    @Override
    public Set<String> getTags() {
        return Collections.singleton("CWE-22");
    }

    @Override
    public Duration getEstimatedEffortPerOccurrence() {
        return Duration.ofMinutes(15);
    }

    @Override
    public TreeVisitor<?, ExecutionContext> getVisitor() {
        return Preconditions.check(new UsesInvocation<>(ZIP_ENTRY_GET_NAME),
                Repeat.repeatUntilStable(new PathTraversalGuardInsertionVisitor<>(
                        ZIP_ENTRY_GET_NAME,
                        "zipEntry",
                        "Bad zip entry",
                        true
                )));
    }
}
