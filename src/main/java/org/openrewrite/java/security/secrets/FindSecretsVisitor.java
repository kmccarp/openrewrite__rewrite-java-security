/*
 * Copyright 2022 the original author or authors.
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
package org.openrewrite.java.security.secrets;

import org.openrewrite.ExecutionContext;
import org.openrewrite.Tree;
import org.openrewrite.TreeVisitor;
import org.openrewrite.internal.ListUtils;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.JavaVisitor;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaType;
import org.openrewrite.java.tree.Space;
import org.openrewrite.java.tree.TextComment;
import org.openrewrite.marker.SearchResult;
import org.openrewrite.yaml.YamlIsoVisitor;
import org.openrewrite.yaml.tree.Yaml;

import static org.openrewrite.Tree.randomId;

public abstract class FindSecretsVisitor extends TreeVisitor<Tree, ExecutionContext> {
    private final String name;

    protected FindSecretsVisitor(String name) {
        this.name = name;
    }

    @Override
    public Tree visit(@Nullable Tree tree, ExecutionContext ctx) {
        if (tree == null) {
            return null;
        } else if (tree instanceof J) {
            tree = new JavaVisitor<ExecutionContext>() {
                @Override
                public Space visitSpace(Space space, Space.Location loc, ExecutionContext ctx) {
                    return space.withComments(ListUtils.map(space.getComments(), comment -> {
                        if (comment instanceof TextComment textComment) {
                            if (isSecret(null, textComment.getText(), ctx)) {
                                return comment.withMarkers(comment.getMarkers()
                                        .compute(new SearchResult(randomId(), name), (s1, s2) -> s1 == null ? s2 : s1));
                            }
                        }
                        return comment;
                    }));
                }

                @Override
                public J.Literal visitLiteral(J.Literal literal, ExecutionContext ctx) {
                    if (literal.getType() == JavaType.Primitive.Null) {
                        return literal;
                    }
                    if (literal.getValue() != null) {
                        if (isSecret(null, literal.getValue().toString(), ctx)) {
                            return SearchResult.found(literal, name);
                        }
                    }
                    return literal;
                }
            }.visit(tree, ctx);
        } else if (tree instanceof Yaml) {
            tree = new YamlIsoVisitor<ExecutionContext>() {
                @Override
                public Yaml.Sequence.Entry visitSequenceEntry(Yaml.Sequence.Entry entry, ExecutionContext ctx) {
                    Yaml.Sequence.Entry ent = super.visitSequenceEntry(entry, ctx);
                    if (ent.getBlock() instanceof Yaml.Scalar) {
                        Yaml.Scalar scalar = (Yaml.Scalar) ent.getBlock();
                        if (isSecret(null, scalar.getValue(), ctx)) {
                            ent = SearchResult.found(ent, name);
                        }
                    }
                    return ent;
                }

                @Override
                public Yaml.Mapping.Entry visitMappingEntry(Yaml.Mapping.Entry entry, ExecutionContext ctx) {
                    Yaml.Mapping.Entry ent = super.visitMappingEntry(entry, ctx);
                    if (ent.getKey() instanceof Yaml.Scalar && ent.getValue() instanceof Yaml.Scalar) {
                        Yaml.Scalar key = (Yaml.Scalar) ent.getKey();
                        Yaml.Scalar val = (Yaml.Scalar) ent.getValue();
                        if (isSecret(key.getValue(), val.getValue(), ctx)) {
                            ent = SearchResult.found(ent, name);
                        }
                    }
                    return ent;
                }
            }.visit(tree, ctx);
        }

        return super.visit(tree, ctx);
    }

    protected abstract boolean isSecret(@Nullable String key, @Nullable String value, ExecutionContext ctx);
}
