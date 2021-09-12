package org.openrewrite.java.security.jackson;

import org.openrewrite.ExecutionContext;
import org.openrewrite.Recipe;
import org.openrewrite.java.JavaParser;
import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.JavaVisitor;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaType;
import org.openrewrite.java.tree.TypeUtils;

public class SecureJacksonDefaultTyping extends Recipe {

    @Override
    public String getDisplayName() {
        return "Secure the use of Jackson default typing";
    }

    @Override
    public String getDescription() {
        return "See the [blog post](https://cowtowncoder.medium.com/on-jackson-cves-dont-panic-here-is-what-you-need-to-know-54cd0d6e8062) on this subject.";
    }

    @Override
    protected JavaVisitor<ExecutionContext> getVisitor() {
        MethodMatcher enableDefaultTyping = new MethodMatcher("com.fasterxml.jackson.databind.ObjectMapper enableDefaultTyping()", true);
        return new JavaVisitor<ExecutionContext>() {
            @Override
            public J visitMethodInvocation(J.MethodInvocation method, ExecutionContext executionContext) {
                if (enableDefaultTyping.matches(method)) {
                    JavaType.Method methodType = TypeUtils.asMethod(method.getType());
                    assert methodType != null;

                    if (methodType.getDeclaringType().getMethods().stream().anyMatch(m -> m.getName().equals("activateDefaultTyping"))) {
                        // Jackson version is 2.10 or above
                        maybeAddImport("com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator");
                        return method.withTemplate(
                                JavaTemplate
                                        .builder(this::getCursor, "#{any(com.fasterxml.jackson.databind.ObjectMapper)}.activateDefaultTyping(BasicPolymorphicTypeValidator.builder().build())")
                                        .imports("com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator")
                                        .javaParser(() -> JavaParser.fromJavaVersion()
                                                .classpath("jackson-databind", "jackson-core")
                                                .build())
                                        .build(),
                                method.getCoordinates().replace(),
                                method.getSelect()
                        );
                    }
                }

                return super.visitMethodInvocation(method, executionContext);
            }
        };
    }
}
