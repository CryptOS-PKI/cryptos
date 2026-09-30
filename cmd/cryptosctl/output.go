package main

/*
Apache License 2.0

Copyright 2026 Shane

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import (
	"encoding/json"
	"fmt"
	"io"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

// output formats supported by -o.
const (
	formatHuman = "human"
	formatJSON  = "json"
	formatYAML  = "yaml"
	formatPEM   = "pem"
)

// renderProto writes msg to w in the requested machine format (json or
// yaml). Human and pem formats are handled per-command, not here.
func renderProto(w io.Writer, msg proto.Message, format string) error {
	jsonBytes, err := protojson.MarshalOptions{Multiline: true, Indent: "  ", UseProtoNames: true}.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	switch format {
	case formatJSON:
		_, err := fmt.Fprintln(w, string(jsonBytes))
		return err
	case formatYAML:
		yamlBytes, err := jsonToYAML(jsonBytes)
		if err != nil {
			return err
		}
		_, err = w.Write(yamlBytes)
		return err
	default:
		return fmt.Errorf("unsupported output format %q (want json or yaml)", format)
	}
}

// jsonToYAML converts a JSON document to YAML by round-tripping through a
// generic value, preserving key order is not guaranteed but field names
// are stable from protojson.
func jsonToYAML(jsonBytes []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(jsonBytes, &v); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}
	out, err := yaml.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encode yaml: %w", err)
	}
	return out, nil
}
