package conf

import (
	"encoding/json"
	"testing"
)

func TestStripJSONComments(t *testing.T) {
	in := `{
	// a comment, with "quotes" and a comma,
	"a": "x // not a comment, \"/* nor this */\"", /* inline */
	"b": [1, 2, /* last */ ],
	"c": {"d": true,},
}`
	var got struct {
		A string
		B []int
		C struct{ D bool }
	}
	if err := json.Unmarshal(stripJSONComments([]byte(in)), &got); err != nil {
		t.Fatalf("Unmarshal() = %v\n%s", err, stripJSONComments([]byte(in)))
	}
	if got.A != `x // not a comment, "/* nor this */"` || len(got.B) != 2 || !got.C.D {
		t.Fatalf("got %+v", got)
	}
	plain := `{"a": [1, 2], "b": "]"}`
	if string(stripJSONComments([]byte(plain))) != plain {
		t.Fatal("plain JSON changed")
	}
}
