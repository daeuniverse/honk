package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"

	parser "github.com/daeuniverse/dae/pkg/config_parser"
)

const commit = "5db27a0028d36e7847bd3796497df952337a20e2"

type object = map[string]any

func params(values []*parser.Param, declaration bool) []object {
	out := make([]object, 0, len(values))
	for _, p := range values {
		value := object{"key": p.Key, "val": p.Val}
		if declaration {
			value["and_functions"] = functions(p.AndFunctions)
			value["annotation"] = params(p.Annotation, false)
		}
		out = append(out, value)
	}
	return out
}

func function(f *parser.Function) object {
	return object{"name": f.Name, "not": f.Not, "params": params(f.Params, false)}
}

func functions(values []*parser.Function) []object {
	out := make([]object, 0, len(values))
	for _, f := range values {
		out = append(out, function(f))
	}
	return out
}

func section(s *parser.Section) object {
	items := make([]object, 0, len(s.Items))
	for _, item := range s.Items {
		switch item.Type {
		case parser.ItemType_Param:
			items = append(items, object{"param": params([]*parser.Param{item.Value.(*parser.Param)}, true)[0]})
		case parser.ItemType_Section:
			items = append(items, object{"section": section(item.Value.(*parser.Section))})
		case parser.ItemType_RoutingRule:
			rule := item.Value.(*parser.RoutingRule)
			items = append(items, object{"rule": object{"and_functions": functions(rule.AndFunctions), "outbound": function(&rule.Outbound)}})
		default:
			panic(fmt.Sprintf("unknown item kind %d", item.Type))
		}
	}
	return object{"name": s.Name, "items": items}
}

func project(input string) (result object) {
	// Malformed inputs can panic in the pinned upstream walker before Parse returns.
	defer func() {
		if failure := recover(); failure != nil {
			result = object{"error": fmt.Sprintf("upstream panic: %v", failure)}
		}
	}()
	sections, err := parser.Parse(input)
	if err != nil {
		return object{"error": err.Error()}
	}
	out := make([]object, 0, len(sections))
	unknown := 0
	for _, s := range sections {
		switch s.Name {
		case "include", "global", "node", "group", "subscription", "routing", "dns", "experimental":
			out = append(out, section(s))
		default:
			unknown++
		}
	}
	return object{"sections": out, "unknown_sections": unknown}
}

func main() {
	version := flag.Bool("version", false, "print upstream commit and Go version")
	flag.Parse()
	if *version {
		fmt.Printf("dae %s; %s\n", commit, runtime.Version())
		return
	}
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(project(string(input))); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
