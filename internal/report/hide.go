package report

import (
	"bytes"
	"cmp"
	"reflect"
	"slices"
	"strings"
)

// Hide replaces every occurrence of each value in the run's text with
// label: every string and byte slice, in every exported field, so the
// JSON, SARIF and HTML reports, the terminal summary and the saved run all
// leave it out. SiegeKit uses it for the values of SIEGEKIT_EXTRA_HEADERS
// (ADR 0070), which reach tool output when the target echoes request
// headers. Empty values are ignored.
func (r *Run) Hide(values []string, label string) {
	var pairs []string
	vs := slices.Clone(values)
	// Longer values first, so one that contains another is hidden whole.
	slices.SortFunc(vs, func(a, b string) int { return cmp.Compare(len(b), len(a)) })
	for _, v := range vs {
		if v != "" {
			pairs = append(pairs, v, label)
		}
	}
	if len(pairs) == 0 {
		return
	}
	hide(reflect.ValueOf(r).Elem(), strings.NewReplacer(pairs...), pairs)
}

func hide(v reflect.Value, r *strings.Replacer, pairs []string) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			hide(v.Elem(), r, pairs)
		}
	case reflect.Interface:
		if !v.IsNil() && v.CanSet() {
			e := reflect.New(v.Elem().Type()).Elem()
			e.Set(v.Elem())
			hide(e, r, pairs)
			v.Set(e)
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if f := v.Field(i); f.CanSet() {
				hide(f, r, pairs)
			}
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			if v.CanSet() && !v.IsNil() {
				b := v.Bytes()
				for i := 0; i < len(pairs); i += 2 {
					b = bytes.ReplaceAll(b, []byte(pairs[i]), []byte(pairs[i+1]))
				}
				v.SetBytes(b)
			}
			return
		}
		for i := range v.Len() {
			hide(v.Index(i), r, pairs)
		}
	case reflect.Array:
		for i := range v.Len() {
			hide(v.Index(i), r, pairs)
		}
	case reflect.Map:
		if v.IsNil() {
			return
		}
		keys := v.MapKeys()
		for _, k := range keys {
			val := reflect.New(v.Type().Elem()).Elem()
			val.Set(v.MapIndex(k))
			hide(val, r, pairs)
			nk := reflect.New(k.Type()).Elem()
			nk.Set(k)
			hide(nk, r, pairs)
			v.SetMapIndex(k, reflect.Value{})
			v.SetMapIndex(nk, val)
		}
	case reflect.String:
		if v.CanSet() {
			v.SetString(r.Replace(v.String()))
		}
	}
}
