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
import org.openrewrite.Tree;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.tree.Comment;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaType;
import org.openrewrite.java.tree.Space;
import org.openrewrite.marker.SearchResult;

import java.time.Duration;
import java.util.*;
import java.util.function.Function;

public class FindTextDirectionChanges extends Recipe {

    public static final char LRE = '\u202A';
    public static final char RLE = '\u202B';
    public static final char LRO = '\u202D';
    public static final char RLO = '\u202E';

    @Override
    public Duration getEstimatedEffortPerOccurrence() {
        return Duration.ofMinutes(5);
    }

    public static final char LRI = '\u2066';
    public static final char RLI = '\u2067';
    public static final char FSI = '\u2068';
    public static final char PDF = '\u202C';
    public static final char PDI = '\u2069';
    public static final Collection<Character> sneakyCodes = Arrays.asList(LRE, RLE, LRO, RLO, LRI, RLI, FSI, PDF, PDI);
    public static final Map<Character, String> charToText = new HashMap<>();

    static {
        charToText.put(LRE, "LRE");
        charToText.put(RLE, "RLE");
        charToText.put(LRO, "LRO");
        charToText.put(RLO, "RLO");
        charToText.put(LRI, "LRI");
        charToText.put(RLI, "RLI");
        charToText.put(FSI, "FSI");
        charToText.put(PDF, "PDF");
        charToText.put(PDI, "PDI");
    }

    @Override
    public String getDisplayName() {
        return "Find text-direction changes";
    }

    @Override
    public String getDescription() {
        return "Finds unicode control characters which can change the direction text is displayed in. " +
               "These control characters can alter how source code is presented to a human reader without affecting its interpretation by tools like compilers. " +
               "So a malicious patch could pass code review while introducing vulnerabilities. " +
               "Note that text direction-changing unicode control characters aren't inherently malicious. " +
               "These characters can appear for legitimate reasons in code written in or dealing with right-to-left languages. " +
               "See: https://trojansource.codes/ for more information.";
    }

    @Override
    public Set<String> getTags() {
        return Collections.singleton("CVE-2021-42574");
    }

    @Override
    protected JavaIsoVisitor<ExecutionContext> getVisitor() {
        return new JavaIsoVisitor<ExecutionContext>() {

            @Override
            public @Nullable J visit(@Nullable Tree tree, ExecutionContext context) {
                J j = super.visit(tree, context);
                Object foundCodes = getCursor().pollMessage("foundSneakyCodes");
                if (j != null && foundCodes != null) {
                    //noinspection unchecked
                    j = SearchResult.found(j, "Found text-direction altering unicode control characters: " +
                                              String.join(",", (Set<String>) foundCodes));
                }

                return j;
            }

            @Override
            public Space visitSpace(Space s, Space.Location loc, ExecutionContext context) {
                Set<String> foundCodes = null;
                if (containsSneakyCodes(s.getWhitespace())) {
                    foundCodes = listSneakyCodes(s.getWhitespace());
                }
                if (containsSneakyCodes(s.getComments(), (Comment c) -> c.printComment(getCursor()))) {
                    if (foundCodes == null) {
                        foundCodes = new HashSet<>();
                    }
                    foundCodes.addAll(listSneakyCodes(s.getComments(), (Comment c) -> c.printComment(getCursor())));
                }
                if (containsSneakyCodes(s.getComments(), Comment::getSuffix)) {
                    if (foundCodes == null) {
                        foundCodes = new HashSet<>();
                    }
                    foundCodes.addAll(listSneakyCodes(s.getComments(), Comment::getSuffix));
                }
                if (foundCodes != null) {
                    getCursor().putMessage("foundSneakyCodes", foundCodes);
                }
                return s;
            }

            @Override
            public J.Literal visitLiteral(J.Literal literal, ExecutionContext context) {
                J.Literal l = super.visitLiteral(literal, context);
                if (l.getType() == JavaType.Primitive.String && l.getValueSource() != null && containsSneakyCodes(l.getValueSource())) {
                    l = SearchResult.found(l, "Found text-direction altering unicode control characters: " +
                                              String.join(",", listSneakyCodes(l.getValueSource())));
                }
                return l;
            }
        };
    }

    private static boolean containsSneakyCodes(String s) {
        for (char c : s.toCharArray()) {
            if (sneakyCodes.contains(c)) {
                return true;
            }
        }
        return false;
    }

    private static <T> boolean containsSneakyCodes(Collection<T> collection, Function<T, String> conversion) {
        for (T t : collection) {
            String s = conversion.apply(t);
            if (containsSneakyCodes(s)) {
                return true;
            }
        }
        return false;
    }

    private static Set<String> listSneakyCodes(String s) {
        Set<String> foundCodes = new HashSet<>();
        for (char c : s.toCharArray()) {
            if (sneakyCodes.contains(c)) {
                foundCodes.add(charToText.get(c));
            }
        }
        return foundCodes;
    }

    private static <T> Set<String> listSneakyCodes(Collection<T> collection, Function<T, String> conversion) {
        Set<String> set = new HashSet<>();
        for (T t : collection) {
            String suffix = conversion.apply(t);
            set.addAll(listSneakyCodes(suffix));
        }
        return set;
    }
}
