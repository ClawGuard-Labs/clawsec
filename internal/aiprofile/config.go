package aiprofile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/onyx/internal/constants"
	"gopkg.in/yaml.v3"
)

type Profile struct {
	svcPorts   map[uint16]string
	modelExt   map[string]struct{}
	procNames  map[string]struct{}
	procCat    map[string]string
	svcCat     map[string]string
	defProcCat string
	defSvcCat  string
}

type fileRoot struct {
	AI aiYAML `yaml:"ai"`
}

type processEntryYAML struct {
	Name     string `yaml:"name"`
	Category string `yaml:"category,omitempty"` 
}

type serviceEntryYAML struct {
	Port     int    `yaml:"port"`
	Name     string `yaml:"name"`
	Category string `yaml:"category,omitempty"`
}

type aiYAML struct {
	Services               []serviceEntryYAML `yaml:"services"`
	ModelExtensions        []string           `yaml:"model_extensions"`
	Processes              []processEntryYAML `yaml:"processes"`
	DefaultProcessCategory string             `yaml:"default_process_category"`
	DefaultServiceCategory string             `yaml:"default_service_category"`
}

func ResolveConfigPath(explicit string) (string, error) {
	tryFile := func(p string) (string, error) {
		abs, err := filepath.Abs(p)
		if err != nil {
			return "", err
		}
		st, err := os.Stat(abs)
		if err != nil {
			return "", err
		}
		if st.IsDir() {
			return "", fmt.Errorf("%s: is a directory", abs)
		}
		return abs, nil
	}

	if explicit != "" {
		return tryFile(explicit)
	}

	var candidates []string
	candidates = append(candidates, "config.yaml", "/etc/onyx/config.yaml")

	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "config.yaml"),
			filepath.Join(dir, "..", "config.yaml"),
		)
	}

	for _, p := range candidates {
		path, err := tryFile(p)
		if err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("config.yaml not found (tried %v); pass --config /path/to/config.yaml or install /etc/onyx/config.yaml (see make install)", candidates)
}

func Load(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root fileRoot
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	a := root.AI
	if len(a.Services) == 0 || len(a.Processes) == 0 || len(a.ModelExtensions) == 0 {
		return nil, fmt.Errorf("config: ai.services, ai.processes, and ai.model_extensions must be non-empty in %q", path)
	}

	p := &Profile{
		svcPorts:   make(map[uint16]string, len(a.Services)),
		modelExt:   make(map[string]struct{}, len(a.ModelExtensions)),
		procNames:  make(map[string]struct{}, len(a.Processes)),
		procCat:    make(map[string]string),
		svcCat:     make(map[string]string),
		defProcCat: strings.TrimSpace(a.DefaultProcessCategory),
		defSvcCat:  strings.TrimSpace(a.DefaultServiceCategory),
	}
	if p.defProcCat == "" {
		p.defProcCat = "other"
	}
	if p.defSvcCat == "" {
		p.defSvcCat = "inference"
	}

	for _, svc := range a.Services {
		if svc.Port < 1 || svc.Port > 65535 {
			return nil, fmt.Errorf("config: invalid ai.services port %d (must be 1–65535)", svc.Port)
		}
		name := strings.TrimSpace(svc.Name)
		if name == "" {
			return nil, fmt.Errorf("config: ai.services entry for port %d needs a non-empty name", svc.Port)
		}
		port16 := uint16(svc.Port)
		if _, dup := p.svcPorts[port16]; dup {
			return nil, fmt.Errorf("config: duplicate ai.services port %d", svc.Port)
		}
		p.svcPorts[port16] = name
		if cat := strings.TrimSpace(svc.Category); cat != "" {
			p.svcCat[name] = cat
		}
	}

	for _, proc := range a.Processes {
		name := strings.TrimSpace(proc.Name)
		if name == "" {
			return nil, fmt.Errorf("config: ai.processes entry with empty name")
		}
		if _, dup := p.procNames[name]; dup {
			return nil, fmt.Errorf("config: duplicate ai.processes name %q", name)
		}
		p.procNames[name] = struct{}{}
		if cat := strings.TrimSpace(proc.Category); cat != "" {
			p.procCat[name] = cat
		}
	}

	for _, ext := range a.ModelExtensions {
		e := strings.TrimSpace(strings.ToLower(ext))
		if e == "" {
			continue
		}
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		p.modelExt[e] = struct{}{}
	}
	if len(p.modelExt) == 0 {
		return nil, fmt.Errorf("config: no valid entries in ai.model_extensions")
	}

	return p, nil
}

func (p *Profile) ServiceNameForPort(port uint16) (string, bool) {
	s, ok := p.svcPorts[port]
	return s, ok
}

func (p *Profile) ServicePorts() map[uint16]string {
	out := make(map[uint16]string, len(p.svcPorts))
	for k, v := range p.svcPorts {
		out[k] = v
	}
	return out
}

func (p *Profile) IsAIProcessComm(comm string) bool {
	_, ok := p.procNames[comm]
	return ok
}

func (p *Profile) IsModelExtension(ext string) bool {
	_, ok := p.modelExt[strings.ToLower(ext)]
	return ok
}

func (p *Profile) ModelBasenameIfMatch(path string) string {
	if path == "" {
		return ""
	}
	if !p.IsModelExtension(constants.FileExt(path)) {
		return ""
	}
	i := strings.LastIndex(path, "/")
	return path[i+1:]
}

func (p *Profile) CategorizeProcess(comm string) string {
	if c, ok := p.procCat[comm]; ok {
		return c
	}
	return p.defProcCat
}

func (p *Profile) CategorizeService(svcName string) string {
	if c, ok := p.svcCat[svcName]; ok {
		return c
	}
	return p.defSvcCat
}
