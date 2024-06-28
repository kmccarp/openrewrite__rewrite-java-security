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
package org.openrewrite.java.security.xml;

import lombok.NoArgsConstructor;
import org.openrewrite.ExecutionContext;
import org.openrewrite.TreeVisitor;
import org.openrewrite.xml.XmlIsoVisitor;
import org.openrewrite.xml.tree.Xml;

import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

@NoArgsConstructor(access = lombok.AccessLevel.PRIVATE)
public final class ExternalDTDAccumulator {

    private static final String PUBLIC_ID_STRING = "PUBLIC";
    private final SortedSet<String> externalDTDs = new TreeSet<>();

    public Set<String> getExternalDTDs() {
        return externalDTDs;
    }

    public TreeVisitor<?, ExecutionContext> scanner() {
        return new XmlIsoVisitor<ExecutionContext>() {
            @Override
            public Xml.DocTypeDecl visitDocTypeDecl(Xml.DocTypeDecl docTypeDecl, ExecutionContext executionContext) {
                if (docTypeDecl.getExternalSubsets() != null) {
                    for (Xml.Element element : docTypeDecl.getExternalSubsets().getElements()) {
                        for (Xml.Ident ident : element.getSubset()) {
                            externalDTDs.add(extractURLFromEntity(ident.getName()));
                        }
                    }
                }
                if (docTypeDecl.getInternalSubset() != null) {
                    if (!docTypeDecl.getInternalSubset().isEmpty()) {
                        if (docTypeDecl.getExternalId() != null) {
                            if ("PUBLIC".equals(docTypeDecl.getExternalId().getName()) && docTypeDecl.getInternalSubset().size() > 1) {
                                externalDTDs.add(docTypeDecl.getInternalSubset().get(1).getName().replace("\"", ""));
                            } else if ("SYSTEM".equals(docTypeDecl.getExternalId().getName())) {
                                externalDTDs.add(docTypeDecl.getInternalSubset().getFirst().getName().replace("\"", ""));
                            }
                        }
                    }
                }

                return super.visitDocTypeDecl(docTypeDecl, executionContext);
            }
        };
    }
    public static ExternalDTDAccumulator create() {
        return new ExternalDTDAccumulator();
    }

    static String extractURLFromEntity(String identName) {
        if (identName.contains(PUBLIC_ID_STRING)) {
            String[] lines = identName.split("\\r?\\n|\\r");
            String dtdPath = lines[lines.length - 1].trim();
            dtdPath = dtdPath.split("\"")[1];
            return dtdPath;
        } else {
            return identName.split("\"")[1];
        }
    }
}
