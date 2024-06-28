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

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ExternalDTDAccumulatorTest {
    @ParameterizedTest
    @MethodSource("provideEntitySplitTestArguments")
    void entitySplit(String initial, String expected) {
        assertEquals(expected, ExternalDTDAccumulator.extractURLFromEntity(initial));
    }

    private static Stream<Arguments> provideEntitySplitTestArguments() {
        return Stream.of(
          Arguments.of("""
              <!ENTITY open-hatch-public
                    PUBLIC "-//Textuality//TEXT Standard open-hatch boilerplate//EN"
                    "http://www.texty.com/boilerplate/OpenHatch.xml">\
              """,
            "http://www.texty.com/boilerplate/OpenHatch.xml"),
          Arguments.of("""
              <!ENTITY hatch-pic
                    SYSTEM "../grafix/OpenHatch.gif"
                    NDATA gif>\
              """,
            "../grafix/OpenHatch.gif")
        );
    }
}
