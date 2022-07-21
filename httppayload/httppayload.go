package main

import "os"

func main() {
	payload := os.Args[1]
	res := reformat(payload)
	print(res)
}

func reformat(s string) string {
	res := ""
	for c := range s {
		switch s[c] {
		case '/':
			res = res + "%2F"
		case ':':
			res = res + "%3A"
		case ' ':
			res = res + "%20"
		case '!':
			res = res + "%21"
		case '"':
			res = res + "%22"
		case '#':
			res = res + "%23"
		case '$':
			res = res + "%24"
		case '%':
			res = res + "%25"
		case '&':
			res = res + "%26"
		case '\'':
			res = res + "%27"
		case '(':
			res = res + "%28"
		case ')':
			res = res + "%29"
		case '*':
			res = res + "%2A"
		case '+':
			res = res + "%2B"
		case ',':
			res = res + "%2C"
		case '-':
			res = res + "%2D"
		case '.':
			res = res + "%2E"
		case ';':
			res = res + "%3B"
		case '<':
			res = res + "%3C"
		case '=':
			res = res + "%3D"
		case '>':
			res = res + "%3E"
		case '?':
			res = res + "%3F"
		case '@':
			res = res + "%40"
		case '[':
			res = res + "%5B"
		case '\\':
			res = res + "%5C"
		case ']':
			res = res + "%5D"
		case '^':
			res = res + "%5E"
		case '_':
			res = res + "%5F"
		case '`':
			res = res + "%60"
		default:
			res = res + string(s[c])
		}
	}
	return res
}
