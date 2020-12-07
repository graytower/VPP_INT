#!/usr/bin/env python2
#
# Copyright (c) 2016,2018 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from string import Template

from jvpp_model import Enum


def generate_enums(work_dir, model, logger):
    logger.debug("Generating enums for %s " % model.json_api_files)

    for t in model.types:
        if not isinstance(t, Enum):
            continue
        logger.debug("Generating DTO for enum %s", t)
        type_class_name = t.java_name
        type_class = _ENUM_TEMPLATE.substitute(
            plugin_package=model.plugin_package,
            c_type_name=t.name,
            json_filename=model.json_api_files,
            json_definition=t.doc,
            java_enum_name=type_class_name,
            constants=_generate_constants(t.constants),
            value_type=t.value.type.java_name
        )
        with open("%s/%s.java" % (work_dir, type_class_name), "w") as f:
            f.write(type_class)

_ENUM_TEMPLATE = Template("""
package $plugin_package.types;

/**
 * <p>This class represents $c_type_name enum definition.
 * <br>It was generated by enums_gen.py based on $json_filename:
 * <pre>
$json_definition
 * </pre>
 */
public enum $java_enum_name {
$constants;

    public final $value_type value;

    $java_enum_name(final $value_type value) {
        this.value = value;
    }
    
    public static $java_enum_name forValue(final $value_type value) {
        for ($java_enum_name enumeration : $java_enum_name.values()) {
            if (value == enumeration.value) {
                return enumeration;
            }
        }
        return null;
    }
}
""")


def _generate_constants(constants):
    return ",\n".join(_CONSTANT_TEMPLATE.substitute(name=c['name'], value=c['value']) for c in constants)

_CONSTANT_TEMPLATE = Template("""    $name($value)""")
