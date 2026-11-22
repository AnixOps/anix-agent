package conf

// stripJSONC removes // and /* */ comments and trailing commas before ] or }
// outside strings, so the result is plain JSON.
func stripJSONC(src []byte) []byte {
	out := make([]byte, 0, len(src))
	comma := -1 // index in out of a comma not yet followed by a value
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '"':
			end := i + 1
			for end < len(src) && src[end] != '"' {
				if src[end] == '\\' {
					end++
				}
				end++
			}
			end = min(end+1, len(src))
			out = append(out, src[i:end]...)
			i = end - 1
			comma = -1
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i+1 < len(src) && src[i+1] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			i += 2
			for i+1 < len(src) && !(src[i] == '*' && src[i+1] == '/') {
				i++
			}
			i++
			out = append(out, ' ')
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			out = append(out, c)
		case c == ']' || c == '}':
			if comma >= 0 {
				out[comma] = ' '
			}
			out = append(out, c)
			comma = -1
		case c == ',':
			comma = len(out)
			out = append(out, c)
		default:
			out = append(out, c)
			comma = -1
		}
	}
	return out
}
