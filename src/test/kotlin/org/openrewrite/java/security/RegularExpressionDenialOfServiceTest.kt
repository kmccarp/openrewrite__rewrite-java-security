package org.openrewrite.java.security

import org.junit.jupiter.api.Test
import org.openrewrite.java.Assertions.java
import org.openrewrite.test.RecipeSpec
import org.openrewrite.test.RewriteTest

class RegularExpressionDenialOfServiceTest: RewriteTest {
    override fun defaults(spec: RecipeSpec) {
        spec.recipe(RegularExpressionDenialOfService())
    }

    @Test
    fun `fix ReDOS for simple string`() = rewriteRun(
        java(
            """
            import java.util.regex.Pattern;

            class Test {
                private static final Pattern testRe = Pattern.compile("(.|\\s)*");
            }
            """,
            """
            import java.util.regex.Pattern;

            class Test {
                private static final Pattern testRe = Pattern.compile("(.|\\n|\\r)*");
            }
            """
        )
    )
}
