package conf

// stripJSONComments returns data without // and /* */ comments and without
// a comma that only whitespace or comments separate from the next ] or }.
// Strings are copied as they are.
func stripJSONComments(data []byte) []byte {
	out := make([]byte, 0, len(data))
	comma := -1 // index in out of a comma not yet followed by a value
	for i := 0; i < len(data); i++ {
		c := data[i]
		switch {
		case c == '"':
			end := i + 1
			for end < len(data) && data[end] != '"' {
				if data[end] == '\\' {
					end++
				}
				end++
			}
			end = min(end+1, len(data))
			out = append(out, data[i:end]...)
			i = end - 1
			comma = -1
			continue
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' {
				i++
			}
			i--
			continue
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			i += 2
			for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
				i++
			}
			i++
			out = append(out, ' ')
			continue
		case c == ']' || c == '}':
			if comma >= 0 {
				out[comma] = ' '
			}
		case c == ',':
			out = append(out, c)
			comma = len(out) - 1
			continue
		}
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			comma = -1
		}
		out = append(out, c)
	}
	return out
}
