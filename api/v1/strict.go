package v1

import (
	"bytes"
	"encoding/json"
	"fmt"

	"kevaso.com/core/api/meta"
)

// DecodeStrict is Decode for what a person wrote: a field the kind doesn't have is an error, never
// dropped (the API server decodes the same way). Defined kinds (KindDefinitions) are checked
// against their schema by the server instead.
func DecodeStrict(data []byte) (meta.Object, KindInfo, error) {
	obj, k, err := Decode(data)
	if err != nil {
		return nil, k, err
	}
	if _, ok := obj.(*Unstructured); ok {
		return obj, k, nil
	}
	strict := k.New()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(strict); err != nil {
		return nil, KindInfo{}, fmt.Errorf("decode %s: %w", k.Kind, err)
	}
	return strict, k, nil
}
