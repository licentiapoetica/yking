package plan

import (
	"fmt"
	"strings"
)

// Unified returns a unified diff of a → b with ctx lines of context, or ""
// if they are equal. Files yking edits are small, so an O(n·m) LCS is fine.
func Unified(aName, bName, a, b string, ctx int) string {
	if a == b {
		return ""
	}
	al, bl := splitLines(a), splitLines(b)
	ops := diffOps(al, bl)

	var out strings.Builder
	fmt.Fprintf(&out, "--- %s\n+++ %s\n", aName, bName)

	// Group ops into hunks separated by more than 2*ctx unchanged lines.
	i := 0
	for i < len(ops) {
		for i < len(ops) && ops[i].kind == ' ' {
			i++
		}
		if i == len(ops) {
			break
		}
		start := max(i-ctx, 0)
		end := i
		for end < len(ops) {
			if ops[end].kind != ' ' {
				end++
				continue
			}
			run := end
			for run < len(ops) && ops[run].kind == ' ' {
				run++
			}
			if run == len(ops) || run-end > 2*ctx {
				end = min(end+ctx, len(ops))
				break
			}
			end = run
		}
		writeHunk(&out, ops[start:end])
		i = end
	}
	return out.String()
}

type op struct {
	kind  byte // ' ', '-', '+'
	text  string
	aLine int // 1-based line in a (for ' ' and '-')
	bLine int // 1-based line in b (for ' ' and '+')
}

func writeHunk(w *strings.Builder, ops []op) {
	aStart, bStart, aCount, bCount := 0, 0, 0, 0
	for _, o := range ops {
		if o.kind != '+' {
			if aStart == 0 {
				aStart = o.aLine
			}
			aCount++
		}
		if o.kind != '-' {
			if bStart == 0 {
				bStart = o.bLine
			}
			bCount++
		}
	}
	// Empty side: unified format uses the line before the hunk.
	if aCount == 0 {
		aStart = ops[0].aLine - 1
	}
	if bCount == 0 {
		bStart = ops[0].bLine - 1
	}
	fmt.Fprintf(w, "@@ -%d,%d +%d,%d @@\n", aStart, aCount, bStart, bCount)
	for _, o := range ops {
		w.WriteByte(o.kind)
		w.WriteString(o.text)
		w.WriteByte('\n')
	}
}

func diffOps(a, b []string) []op {
	n, m := len(a), len(b)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var ops []op
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && a[i] == b[j]:
			ops = append(ops, op{' ', a[i], i + 1, j + 1})
			i++
			j++
		case i < n && (j == m || lcs[i+1][j] >= lcs[i][j+1]):
			ops = append(ops, op{'-', a[i], i + 1, j + 1})
			i++
		default:
			ops = append(ops, op{'+', b[j], i + 1, j + 1})
			j++
		}
	}
	return ops
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n")
}
