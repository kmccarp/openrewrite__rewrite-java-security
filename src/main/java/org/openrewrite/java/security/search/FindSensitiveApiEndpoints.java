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
package org.openrewrite.java.security.search;

import lombok.EqualsAndHashCode;
import lombok.Value;
import org.openrewrite.*;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.AnnotationMatcher;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.security.table.SensitiveApiEndpoints;
import org.openrewrite.java.tree.Expression;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaType;
import org.openrewrite.java.tree.TypeUtils;
import org.openrewrite.marker.SearchResult;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.toList;

@Value
@EqualsAndHashCode(callSuper = false)
public class FindSensitiveApiEndpoints extends Recipe {
    @Option(displayName = "Field names",
            description = "Field names to search for.",
            example = "password,dateOfBirth,dob,ssn")
    List<String> fieldNames;

    @Option(displayName = "Transitive",
            description = """
                          Find model objects that contain other model \
                          objects that contain sensitive data.\
                          """,
            required = false)
    @Nullable
    Boolean transitive;

    transient SensitiveApiEndpoints endpoints = new SensitiveApiEndpoints(this);

    @Override
    public String getDisplayName() {
        return "Find sensitive API endpoints";
    }

    @Override
    public String getDescription() {
        return """
               Find data models exposed by REST APIs that contain \
               sensitive information like PII and secrets.\
               """;
    }

    @Override
    public TreeVisitor<?, ExecutionContext> getVisitor() {
        return new JavaIsoVisitor<ExecutionContext>() {
            @Override
            public J.MethodDeclaration visitMethodDeclaration(J.MethodDeclaration method, ExecutionContext ctx) {
                Endpoint endpoint = Endpoint.spring(getCursor()).orElse(Endpoint.jaxrs(getCursor()).orElse(null));
                if (endpoint == null) {
                    return super.visitMethodDeclaration(method, ctx);
                }
                if (method.getReturnTypeExpression() == null) {
                    return method;
                }
                List<List<JavaType.Method>> sensitive = sensitiveFieldPaths(requireNonNull(method.getReturnTypeExpression()).getType());
                if (sensitive.isEmpty()) {
                    return method;
                }

                List<String> sensitivePaths = sensitive.stream()
                        .map(path -> path.stream()
                                .map(v -> requireNonNull(TypeUtils.asFullyQualified(v.getDeclaringType())).getFullyQualifiedName() + "#" + v.getName())
                                .collect(Collectors.joining("->")))
                        .collect(toList());

                for (String sensitivePath : sensitivePaths) {
                    String fieldName = sensitivePaths.getLast();
                    endpoints.insertRow(ctx, new SensitiveApiEndpoints.Row(
                            getCursor().firstEnclosingOrThrow(J.CompilationUnit.class).getSourcePath().toString(),
                            method.getSimpleName(),
                            endpoint.getMethod(),
                            endpoint.getPath(),
                            fieldName.substring(fieldName.lastIndexOf("#") + 1),
                            sensitivePath
                    ));
                }

                return method.withReturnTypeExpression(SearchResult.found(method.getReturnTypeExpression(),
                        String.join("\n", sensitivePaths)));
            }
        };
    }

    private List<List<JavaType.Method>> sensitiveFieldPaths(@Nullable JavaType type) {
        List<List<JavaType.Method>> sensitive = new ArrayList<>(1);
        Set<String> seen = new HashSet<>();
        sensitiveFieldPathsRecursive(type, emptyList(), sensitive, seen);
        return sensitive;
    }

    private void sensitiveFieldPathsRecursive(@Nullable JavaType type, List<JavaType.Method> path,
                                              List<List<JavaType.Method>> sensitive, Set<String> seen) {
        JavaType.FullyQualified fq = TypeUtils.asFullyQualified(type);
        if (type instanceof JavaType.Parameterized parameterized) {
            for (JavaType typeParameter : parameterized.getTypeParameters()) {
                sensitiveFieldPathsRecursive(typeParameter, path, sensitive, seen);
            }
        } else if (fq != null) {
            if (!seen.add(fq.getFullyQualifiedName())) {
                return;
            }

            Iterator<JavaType.Method> visibleMethods = fq.getVisibleMethods();
            nextMethod:
            while (visibleMethods.hasNext()) {
                JavaType.Method method = visibleMethods.next();
                if (!method.getName().startsWith("get")) {
                    continue;
                }
                List<JavaType.Method> nextPath = new ArrayList<>(path);
                nextPath.add(method);
                for (String fieldName : fieldNames) {
                    if (method.getName().substring(3).equalsIgnoreCase(fieldName)) {
                        sensitive.add(nextPath);
                        continue nextMethod;
                    }
                }
                if (!Boolean.FALSE.equals(transitive)) {
                    sensitiveFieldPathsRecursive(method.getReturnType(), nextPath, sensitive, seen);
                }
            }
        }
    }

    @Value
    private static class Endpoint {
        private static final List<AnnotationMatcher> SPRING_ENDPOINTS = Stream.of("Request", "Get", "Post", "Put", "Delete", "Patch")
                .map(method -> new AnnotationMatcher("@org.springframework.web.bind.annotation." + method + "Mapping"))
                .collect(toList());

        private static final List<AnnotationMatcher> JAXRS_PATH = singletonList(
                new AnnotationMatcher("@javax.ws.rs.Path"));

        String method;
        String path;

        public static Optional<Endpoint> spring(Cursor cursor) {
            AtomicReference<J.Annotation> requestAnnotation = new AtomicReference<>();
            String path =
                    cursor.getPathAsStream()
                            .filter(J.ClassDeclaration.class::isInstance)
                            .map(classDecl -> ((J.ClassDeclaration) classDecl).getAllAnnotations().stream()
                                    .filter(a -> hasRequestMapping(a, SPRING_ENDPOINTS))
                                    .findAny()
                                    .map(classMapping -> {
                                        requestAnnotation.set(classMapping);
                                        return getArg(classMapping, "value", "");
                                    })
                                    .orElse(null))
                            .filter(Objects::nonNull)
                            .collect(Collectors.joining("/")) +
                    cursor.getPathAsStream()
                            .filter(J.MethodDeclaration.class::isInstance)
                            .map(classDecl -> ((J.MethodDeclaration) classDecl).getAllAnnotations().stream()
                                    .filter(a -> hasRequestMapping(a, SPRING_ENDPOINTS))
                                    .findAny()
                                    .map(methodMapping -> {
                                        requestAnnotation.set(methodMapping);
                                        return getArg(methodMapping, "value", "");
                                    })
                                    .orElse(null))
                            .filter(Objects::nonNull)
                            .collect(Collectors.joining("/"));
            path = path.replace("//", "/");

            if (requestAnnotation.get() == null) {
                return Optional.empty();
            }

            JavaType.FullyQualified type = TypeUtils.asFullyQualified(requestAnnotation.get().getType());
            assert type != null;
            String httpMethod = type.getClassName().startsWith("Request") ?
                    getArg(requestAnnotation.get(), "method", "GET") :
                    type.getClassName().replace("Mapping", "").toUpperCase();

            return Optional.of(new Endpoint(httpMethod, path));
        }

        public static Optional<Endpoint> jaxrs(Cursor cursor) {
            String path =
                    cursor.getPathAsStream()
                            .filter(J.ClassDeclaration.class::isInstance)
                            .map(classDecl -> ((J.ClassDeclaration) classDecl).getAllAnnotations().stream()
                                    .filter(a -> hasRequestMapping(a, JAXRS_PATH))
                                    .findAny()
                                    .map(classMapping -> getArg(classMapping, "value", ""))
                                    .orElse(null))
                            .filter(Objects::nonNull)
                            .collect(Collectors.joining("/")) +
                    cursor.getPathAsStream()
                            .filter(J.MethodDeclaration.class::isInstance)
                            .map(classDecl -> ((J.MethodDeclaration) classDecl).getAllAnnotations().stream()
                                    .filter(a -> hasRequestMapping(a, JAXRS_PATH))
                                    .findAny()
                                    .map(methodMapping -> getArg(methodMapping, "value", ""))
                                    .orElse(null))
                            .filter(Objects::nonNull)
                            .collect(Collectors.joining("/"));
            path = path.replace("//", "/");

            String httpMethod = null;
            for (J.Annotation ann : cursor.firstEnclosingOrThrow(J.MethodDeclaration.class).getAllAnnotations()) {
                JavaType.FullyQualified type = TypeUtils.asFullyQualified(ann.getType());
                if (type == null) {
                    continue;
                }
                if ("GET".equals(type.getClassName()) || "POST".equals(type.getClassName()) ||
                    "DELETE".equals(type.getClassName())) {
                    httpMethod = type.getClassName();
                    break;
                }
                if (TypeUtils.isOfClassType(type, "javax.ws.rs.HttpMethod")) {
                    httpMethod = getArg(ann, "value", "GET");
                    break;
                }
            }

            if (httpMethod == null) {
                return Optional.empty();
            }

            return Optional.of(new Endpoint(httpMethod, path));
        }

        private static String getArg(J.Annotation annotation, String key, String defaultValue) {
            if (annotation.getArguments() != null) {
                for (Expression argument : annotation.getArguments()) {
                    if (argument instanceof J.Literal literal) {
                        //noinspection ConstantConditions
                        return (String) literal.getValue();
                    } else if (argument instanceof J.Assignment arg) {
                        if (((J.Identifier) arg.getVariable()).getSimpleName().equals(key)) {
                            if (arg.getAssignment() instanceof J.FieldAccess) {
                                return ((J.FieldAccess) arg.getAssignment()).getSimpleName();
                            } else if (arg.getAssignment() instanceof J.Identifier) {
                                return ((J.Identifier) arg.getAssignment()).getSimpleName();
                            } else if (arg.getAssignment() instanceof J.Literal) {
                                //noinspection ConstantConditions
                                return (String) ((J.Literal) arg.getAssignment()).getValue();
                            }
                        }
                    }
                }
            }
            return defaultValue;
        }

        @SuppressWarnings("SameParameterValue")
        private static boolean hasRequestMapping(J.Annotation ann, List<AnnotationMatcher> endpointMatchers) {
            for (AnnotationMatcher restEndpoint : endpointMatchers) {
                if (restEndpoint.matches(ann)) {
                    return true;
                }
            }
            return false;
        }
    }
}
