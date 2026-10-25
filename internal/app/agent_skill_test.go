package app

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgentSkillPackage(t *testing.T) {
	files, e := agentSkillFiles()
	if e != nil {
		t.Fatal(e)
	}
	found := map[string]string{}
	for _, file := range files {
		found[file.Path] = file.Content
		if strings.Contains(file.Path, "..") || strings.HasPrefix(file.Path, "/") {
			t.Fatal("unsafe archive path")
		}
	}
	skill := found["aegis-waf/SKILL.md"]
	if !strings.HasPrefix(skill, "---\nname: aegis-waf\n") || !strings.Contains(skill, "get_management_contract") || !strings.Contains(skill, "references/playbooks.md") {
		t.Fatal("invalid skill entry point")
	}
	for _, path := range []string{"aegis-waf/references/playbooks.md", "aegis-waf/references/permissions.md", "aegis-waf/LICENSE"} {
		if found[path] == "" {
			t.Fatal("missing bundled reference", path)
		}
	}
	a := &App{}
	w := httptest.NewRecorder()
	if e = a.downloadAgentSkill(w, httptest.NewRequest("GET", "http://management/api/agent-access/skill", nil), identity{}); e != nil {
		t.Fatal(e)
	}
	if w.Header().Get("Content-Type") != "application/zip" {
		t.Fatal("missing archive content type")
	}
	archive, e := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if e != nil {
		t.Fatal(e)
	}
	if len(archive.File) != len(files) {
		t.Fatal("archive omitted files")
	}
	for _, file := range archive.File {
		reader, e := file.Open()
		if e != nil {
			t.Fatal(e)
		}
		data, e := io.ReadAll(reader)
		reader.Close()
		if e != nil || string(data) != found[file.Name] {
			t.Fatal("archive differs from MCP skill", file.Name)
		}
	}
}
