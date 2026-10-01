// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/datapath/config/types"
)

// applyConstants sets the values of BPF C runtime configurables defined using
// the DECLARE_CONFIG macro.
func applyConstants(spec *ebpf.CollectionSpec, obj any) error {
	if obj == nil {
		return nil
	}

	constants, err := config.Map(obj)
	if err != nil {
		return fmt.Errorf("converting struct to map: %w", err)
	}

	for name, value := range constants {
		constName := types.ConstantPrefix + name

		v, ok := spec.Variables[constName]
		if !ok {
			return fmt.Errorf("can't set non-existent Variable %s", name)
		}

		if v.SectionName != types.ConstantSection {
			return fmt.Errorf("can only set Cilium config variables in section %s (got %s:%s), ", types.ConstantSection, v.SectionName, name)
		}

		if err := v.Set(value); err != nil {
			return fmt.Errorf("setting Variable %s: %w", name, err)
		}
	}

	return nil
}

// iterAny returns a sequence that yields the elements of the given object if it
// is a slice, or the object itself otherwise. Nil values are never yielded.
func iterAny(obj any) iter.Seq[any] {
	return func(yield func(any) bool) {
		if obj == nil {
			return
		}

		if reflect.TypeOf(obj).Kind() != reflect.Slice {
			yield(obj)
			return
		}

		rv := reflect.ValueOf(obj)
		for i := 0; i < rv.Len(); i++ {
			v := rv.Index(i)
			if v.IsNil() {
				continue
			}
			if !yield(v.Interface()) {
				return
			}
		}
	}
}

// typeName returns the name of the type of the given object. If the object is
// a pointer, the name of the pointed-to type is returned.
func typeName(i any) string {
	if i == nil {
		return ""
	}
	typ := reflect.TypeOf(i)
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	return typ.String()
}

// printConstants returns a string representation of a given consts object for
// logging purposes. Since the input can be a slice of objects, they need to be
// printed separately for struct field names to show up using %#v.
func printConstants(objs any) string {
	var frags []string
	for obj := range iterAny(objs) {
		frags = append(frags, fmt.Sprintf("%#v", obj))
	}
	return "[" + strings.Join(frags, ", ") + "]"
}

// configDumpLayout defines the layout of the JSON file written by
// dumpConstants.
//
// An example of the file format is:
//
//	{
//	  "objects": [
//	    {
//	      "name": "config.BPFHost",
//	      "values": {
//	        "AllowICMPFragNeeded": true,
//	        "DeviceMTU": 1500
//	    }
//	  ],
//	  "variables": {
//	    "__config_allow_icmp_frag_needed": "AQ==",
//	    "__config_device_mtu": "3AU="
//	  }
//	}
type configDumpLayout struct {
	Objects   []objDumpLayout   `json:"objects"`
	Variables map[string][]byte `json:"variables"`
}

type objDumpLayout struct {
	Name   string `json:"name"`
	Values any    `json:"values"`
}

// dumpConstants writes the values of BPF C runtime configurables defined using
// the DECLARE_CONFIG macro to a JSON file at
// [CollectionOptions.ConfigDumpPath].
//
// This file can be used by tooling to read back the config values for
// troubleshooting purposes. The document has the layout of [configDumpLayout]
// and is produced in a single pass into one buffer, without building
// intermediate slices or maps just to hand them to a reflective encoder.
func dumpConstants(spec *ebpf.CollectionSpec, opts *CollectionOptions) error {
	if opts.ConfigDumpPath == "" {
		return nil
	}

	// Collect constant variable names (sorted, for deterministic output, as
	// encoding/json does for maps) and estimate the output size in one pass.
	names := make([]string, 0, len(spec.Variables))
	size := len(`{"objects":[],"variables":{}}`) + 1 + 256
	for name, v := range spec.Variables {
		if v.SectionName != types.ConstantSection {
			continue
		}
		names = append(names, name)
		size += len(name) + base64.StdEncoding.EncodedLen(len(v.Value)) + 6
	}
	slices.Sort(names)

	b := make([]byte, 0, size)
	b = append(b, `{"objects":[`...)
	b, err := appendConstantObjects(b, opts.Constants)
	if err != nil {
		return fmt.Errorf("dump constants: %w", err)
	}

	// Write out marshaled variable values for replaying BPF loads later.
	b = append(b, `],"variables":{`...)
	for i, name := range names {
		if i > 0 {
			b = append(b, ',')
		}
		b = appendJSONString(b, name)
		b = append(b, ':')
		val := spec.Variables[name].Value
		if val == nil {
			b = append(b, "null"...)
			continue
		}
		b = append(b, '"')
		b = base64.StdEncoding.AppendEncode(b, val)
		b = append(b, '"')
	}
	b = append(b, "}}\n"...)

	return writeConfigDump(opts.ConfigDumpPath, b)
}

// writeConfigDump writes data to path, creating parent directories only when
// the initial write reports that they are missing.
func writeConfigDump(path string, data []byte) error {
	err := os.WriteFile(path, data, 0o666)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return fmt.Errorf("create directory: %w", err)
		}
		err = os.WriteFile(path, data, 0o666)
	}
	if err != nil {
		return fmt.Errorf("write config file: %w", err)
	}
	return nil
}

// appendConstantObjects appends the JSON encoding of each object in obj (a
// single object or a slice of objects, with nil elements skipped) as
// objDumpLayout entries, separated by commas.
func appendConstantObjects(b []byte, obj any) ([]byte, error) {
	if obj == nil {
		return b, nil
	}

	rv := reflect.ValueOf(obj)
	if rv.Kind() != reflect.Slice {
		return appendObjDump(b, obj, true)
	}

	first := true
	for i := 0; i < rv.Len(); i++ {
		v := rv.Index(i)
		switch v.Kind() {
		case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice,
			reflect.Func, reflect.Chan, reflect.UnsafePointer:
			if v.IsNil() {
				continue
			}
		}
		var err error
		b, err = appendObjDump(b, v.Interface(), first)
		if err != nil {
			return b, err
		}
		first = false
	}
	return b, nil
}

// appendObjDump appends a single objDumpLayout entry for obj.
func appendObjDump(b []byte, obj any, first bool) ([]byte, error) {
	values, err := json.Marshal(obj)
	if err != nil {
		return b, err
	}
	if !first {
		b = append(b, ',')
	}
	b = append(b, `{"name":`...)
	b = appendJSONString(b, typeName(obj))
	b = append(b, `,"values":`...)
	b = append(b, values...)
	b = append(b, '}')
	return b, nil
}

// appendJSONString appends s as a JSON string literal. Plain printable ASCII
// (the common case for C identifiers and Go type names) is appended directly;
// anything requiring escaping is delegated to encoding/json.
func appendJSONString(b []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c >= 0x7f || c == '"' || c == '\\' || c == '<' || c == '>' || c == '&' {
			q, err := json.Marshal(s)
			if err != nil {
				// Marshaling a string cannot fail; keep a safe fallback.
				return append(b, `""`...)
			}
			return append(b, q...)
		}
	}
	b = append(b, '"')
	b = append(b, s...)
	return append(b, '"')
}
