// builddb: OSV JSON 파일 디렉터리에서 govulncheck v1.9.0이 읽는 v1 DB를 만든다.
//
// 출력 구조 (golang.org/x/vuln@v1.9.0 internal/client/schema.go, index.go와 같음):
//
//	<out>/index/db.json       {"modified": 가장 늦은 entry.modified}
//	<out>/index/modules.json  [{"path", "vulns": [{"id","modified","fixed"}]}] path, id 순 정렬
//	<out>/ID/<ID>.json        원본 OSV 파일을 그대로 복사
//
// fixed 값은 v1.9.0 internal/semver/fixed.go NonSupersededFix와 같은 규칙으로 계산한다.
// 사용: go run . -src <osv json 디렉터리> -out <db 디렉터리> [-prefix GO-] [-modified-fallback RFC3339]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

type rangeEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type osvRange struct {
	Type   string       `json:"type"`
	Events []rangeEvent `json:"events"`
}

type affected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges []osvRange `json:"ranges"`
}

type entry struct {
	ID       string     `json:"id"`
	Modified time.Time  `json:"modified"`
	Affected []affected `json:"affected"`
}

type moduleVuln struct {
	ID       string    `json:"id"`
	Modified time.Time `json:"modified"`
	Fixed    string    `json:"fixed,omitempty"`
}

type moduleMeta struct {
	Path  string       `json:"path"`
	Vulns []moduleVuln `json:"vulns"`
}

func canon(s string) string {
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "go")
	return "v" + s
}

func less(a, b string) bool { return semver.Compare(canon(a), canon(b)) < 0 }

// nonSupersededFix: x/vuln v1.9.0 internal/semver/fixed.go 와 같은 규칙.
func nonSupersededFix(ranges []osvRange) string {
	var latest string
	for _, r := range ranges {
		if r.Type != "SEMVER" {
			continue
		}
		for _, e := range r.Events {
			if e.Fixed != "" && less(latest, e.Fixed) {
				latest = e.Fixed
			}
		}
		for _, e := range r.Events {
			if e.Introduced != "" && e.Introduced != "0" && less(latest, e.Introduced) {
				latest = ""
				break
			}
		}
	}
	return latest
}

func main() {
	src := flag.String("src", "", "OSV JSON 디렉터리")
	out := flag.String("out", "", "출력 DB 디렉터리 (비어 있어야 함)")
	prefix := flag.String("prefix", "GO-", "이 접두어로 시작하는 ID만 넣는다")
	fallback := flag.String("modified-fallback", "", "모든 entry의 modified가 0일 때 db.json에 넣을 시각 (RFC3339). golang/vulndb 저장소 파일은 modified가 0이다")
	flag.Parse()
	if *src == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: builddb -src DIR -out DIR")
		os.Exit(2)
	}
	files, err := filepath.Glob(filepath.Join(*src, "*.json"))
	if err != nil {
		panic(err)
	}
	sort.Strings(files)
	if err := os.MkdirAll(filepath.Join(*out, "ID"), 0o755); err != nil {
		panic(err)
	}
	if err := os.MkdirAll(filepath.Join(*out, "index"), 0o755); err != nil {
		panic(err)
	}
	var dbModified time.Time
	modules := map[string]*moduleMeta{}
	n := 0
	for _, f := range files {
		base := filepath.Base(f)
		if !strings.HasPrefix(base, *prefix) {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			panic(err)
		}
		var e entry
		if err := json.Unmarshal(b, &e); err != nil {
			panic(fmt.Errorf("%s: %w", f, err))
		}
		if base != e.ID+".json" {
			panic(fmt.Errorf("파일 이름과 ID가 다르다: %s vs %s", base, e.ID))
		}
		if e.Modified.After(dbModified) {
			dbModified = e.Modified
		}
		for _, a := range e.Affected {
			if a.Package.Ecosystem != "Go" {
				continue
			}
			m, ok := modules[a.Package.Name]
			if !ok {
				m = &moduleMeta{Path: a.Package.Name, Vulns: []moduleVuln{}}
				modules[a.Package.Name] = m
			}
			m.Vulns = append(m.Vulns, moduleVuln{ID: e.ID, Modified: e.Modified, Fixed: nonSupersededFix(a.Ranges)})
		}
		if err := os.WriteFile(filepath.Join(*out, "ID", base), b, 0o644); err != nil {
			panic(err)
		}
		n++
	}
	list := make([]*moduleMeta, 0, len(modules))
	for _, m := range modules {
		sort.SliceStable(m.Vulns, func(i, j int) bool { return m.Vulns[i].ID < m.Vulns[j].ID })
		list = append(list, m)
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].Path < list[j].Path })
	mb, err := json.Marshal(list)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(*out, "index", "modules.json"), mb, 0o644); err != nil {
		panic(err)
	}
	if dbModified.IsZero() && *fallback != "" {
		t, err := time.Parse(time.RFC3339, *fallback)
		if err != nil {
			panic(err)
		}
		dbModified = t.UTC()
		fmt.Println("note: entry modified 값이 모두 0이라 db.json에 -modified-fallback 값을 넣었다")
	}
	db, err := json.Marshal(map[string]time.Time{"modified": dbModified})
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(*out, "index", "db.json"), db, 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("entries=%d modules=%d db_modified=%s\n", n, len(list), dbModified.Format(time.RFC3339Nano))
}
