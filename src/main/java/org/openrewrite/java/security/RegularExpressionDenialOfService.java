package org.openrewrite.java.security;

import lombok.AllArgsConstructor;
import org.openrewrite.ExecutionContext;
import org.openrewrite.Incubating;
import org.openrewrite.Recipe;
import org.openrewrite.TreeVisitor;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaType;

@Incubating(since = "1.15.0")
public class RegularExpressionDenialOfService extends Recipe  {

    @Override
    public String getDisplayName() {
        return "Regular Expression Denial of Service (ReDOS)";
    }

    @Override
    protected TreeVisitor<?, ExecutionContext> getVisitor() {
        return new RegularExpressionDenialOfServiceVisitor<>();
    }

    /**
     * See <a href="https://docs.google.com/spreadsheets/d/16beyWhp7Ied7QEA8S_OvUeFFGfQAEP34/edit#gid=1018601927">Google Doc</a>
     */
    @AllArgsConstructor
    enum KnownVulnerableRegex {
        URL_VALIDATOR(
                "/^(?:(?:(?:https?|ftp):)?\\/\\/)(?:\\S+(?::\\S*)?@)?(?:(?!(?:10|127)(?:\\.\\d{1,3}){3})(?!(?:169\\.254|192\\.168)(?:\\.\\d{1,3}){2})(?!172\\.(?:1[6-9]|2\\d|3[0-1])(?:\\.\\d{1,3}){2})(?:[1-9]\\d?|1\\d\\d|2[01]\\d|22[0-3])(?:\\.(?:1?\\d{1,2}|2[0-4]\\d|25[0-5])){2}(?:\\.(?:[1-9]\\d?|1\\d\\d|2[0-4]\\d|25[0-4]))|(?:(?:[a-z\\u00a1-\\uffff0-9]-*)*[a-z\\u00a1-\\uffff0-9]+)(?:\\.(?:[a-z\\u00a1-\\uffff0-9]-*)*[a-z\\u00a1-\\uffff0-9]+)*(?:\\.(?:[a-z\\u00a1-\\uffff]{2,})).?)(?::\\d{2,5})?(?:[/?#]\\S*)?$/i",
                "/^(?:(?:(?:https?|ftp):)?\\/\\/)(?:\\S+(?::\\S*)?@)?(?:(?!(?:10|127)(?:\\.\\d{1,3}){3})(?!(?:169\\.254|192\\.168)(?:\\.\\d{1,3}){2})(?!172\\.(?:1[6-9]|2\\d|3[0-1])(?:\\.\\d{1,3}){2})(?:[1-9]\\d?|1\\d\\d|2[01]\\d|22[0-3])(?:\\.(?:1?\\d{1,2}|2[0-4]\\d|25[0-5])){2}(?:\\.(?:[1-9]\\d?|1\\d\\d|2[0-4]\\d|25[0-4]))|(?:(?:[a-z0-9\\u00a1-\\uffff][a-z0-9\\u00a1-\\uffff_-]{0,62})?[a-z0-9\\u00a1-\\uffff]\\.)+(?:[a-z\\u00a1-\\uffff]{2,}\\.?))(?::\\d{2,5})?(?:[/?#]\\S*)?$/i"
        ),
        ANY_NEWLINE(
                "(.|\\s)*",
                "(.|\\n|\\r)*"
        ),
        SKIP_FIRST_BIT_OF_CSV_LIST(
                "(?:.*,)*",
                "(?:^|,)"
        ),
        SELECT_ALL_NEWLINE_TYPES_ONE_OR_MORE(
                "(\\r\\n|\\r|\\n)+",
                "(\\r|\\n)+"
        ),
        SELECT_ALL_NEWLINE_TYPES_NONE_OR_MORE(
                "(\\r\\n|\\r|\\n)*",
                "(\\r|\\n)*"
        ),
        SELECT_ALL_INCLUDING_ESCAPED_CHARACTERS(
                "(\\?.)*",
                ".*"
        ),
        PARTIAL_EMAIL_VALIDATOR(
                "([^@\\s]+\\.)+",
                "([^@\\s.]+\\.)+"
        ),
        DECIMAL_NUMBER_VALIDATOR(
                "(\\d+\\.?)*",
                "((\\d+\\.)*|\\d*)"
        ),
        HTML_COMMENT_MATCHING(
                "<!--([^-]+|[-][^-]+)*-->",
                "<!---->|<!--(?:-?[^>-])(?:-?[^-])*-->"
        ),
        BOLD_TEXT_MARKDOWN(
                "(?:__|[\\s\\S])+",
                "(?:[^_]|__)+"
        ),
        COMMENT_MATCHING_IN_JAVASCRIPT(
                "(\\s|\\/\\*.*?\\*\\/)*",
                "(\\s|\\/\\*([^*]|\\*(?!\\/))*?\\*\\/)*"
        ),
        EMAIL_VALIDATION(
                "^((([a-z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])+(\\.([a-z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])|(\\\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))@((([a-z]|\\d|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])|(([a-z]|\\d|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])([a-z]|\\d|-|\\.|_|~|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])*([a-z]|\\d|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])))\\.)+(([a-z]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])|(([a-z]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])([a-z]|\\d|-|\\.|_|~|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])*([a-z]|[\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF])))\\.?$",
                "^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
        );

        final String bad;
        final String good;
    }

    private static class RegularExpressionDenialOfServiceVisitor<P> extends JavaIsoVisitor<P> {
        @Override
        public J.Literal visitLiteral(J.Literal literal, P p) {
            if (literal.getType() == JavaType.Primitive.String) {
                for (KnownVulnerableRegex regex : KnownVulnerableRegex.values()) {
                    if (literal.getValue().toString().contains(regex.bad)) {
                        String valueBad = literal.getValue().toString();
                        String replacement = valueBad.replace(regex.bad, regex.good);
                        return literal.withValue(replacement).withValueSource("\"" + replacement + "\"");
                    }
                }
            }
            return super.visitLiteral(literal, p);
        }
    }
}
