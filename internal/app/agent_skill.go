package app

import (
	"archive/zip"
	"bytes"
	"context"
	"io/fs"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	bundled "github.com/nextgridit-team/Aegis-WAF/skills"
)

type agentSkillFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

func agentSkillFiles() ([]agentSkillFile, error) {
	files := []agentSkillFile{}
	e := fs.WalkDir(bundled.Files, "aegis-waf", func(path string, entry fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if entry.IsDir() {
			return nil
		}
		data, e := bundled.Files.ReadFile(path)
		if e != nil {
			return e
		}
		files = append(files, agentSkillFile{path, string(data)})
		return nil
	})
	return files, e
}
func (a *App) downloadAgentSkill(w http.ResponseWriter, r *http.Request, _ identity) error {
	files, e := agentSkillFiles()
	if e != nil {
		return e
	}
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for _, file := range files {
		entry, e := writer.Create(file.Path)
		if e != nil {
			return e
		}
		if _, e = entry.Write([]byte(file.Content)); e != nil {
			return e
		}
	}
	if e = writer.Close(); e != nil {
		return e
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="aegis-waf.zip"`)
	w.WriteHeader(200)
	_, e = w.Write(archive.Bytes())
	return e
}
func (a *App) addAgentSkill(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{Name: "get_agent_skill", Description: "Read the bundled portable Aegis WAF SKILL.md and supporting permissions/playbook references. Import into a skill-capable agent, or adapt to your operator's own playbook. Documentation grants no permissions and contains no credentials or executable scripts.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, func(ctx context.Context, req *mcp.CallToolRequest, input struct{}) (*mcp.CallToolResult, any, error) {
		files, e := agentSkillFiles()
		if e != nil {
			return agentError("skill bundle unavailable"), nil, nil
		}
		return nil, map[string]any{"name": "aegis-waf", "version": "1.0.0", "files": files}, nil
	})
}
