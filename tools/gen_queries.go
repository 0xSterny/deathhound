package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

type QueryFile struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Query       string `yaml:"query"`
	Category    string `yaml:"category"`
}

var packageTemplate = template.Must(template.New("").Parse(`package library

import (
	"fmt"
)

// NamedQuery represents a pre-defined Cypher query
type NamedQuery struct {
	Name        string
	Description string
	Category    string
	Cypher      string
}

// Queries is the map of all available named queries
var Queries = map[string]NamedQuery{
{{- range $key, $val := . }}
	"{{ $key }}": {
		Name:        "{{ $val.Name }}",
		Description: "{{ $val.Description }}",
		Category:    "{{ $val.Category }}",
		Cypher: ` + "`" + `
{{ $val.Query }}
` + "`" + `,
	},
{{- end }}
}

// GetQuery returns the Cypher string for a given mode name
func GetQuery(mode string) (string, error) {
	if q, ok := Queries[mode]; ok {
		return q.Cypher, nil
	}
	return "", fmt.Errorf("unknown mode: %s", mode)
}
`))

func main() {
	var inputPath string
	var outputPath string
	var help bool

	flag.StringVar(&inputPath, "in", "temp_queries/queries", "Input file or directory containing YAML queries")
	flag.StringVar(&outputPath, "out", "internal/library/library.go", "Output Go file")
	flag.BoolVar(&help, "h", false, "Show help message")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "DeathHound Library Generator\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  gen.exe -in <path> -out <path>\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nYAML Structure:\n")
		fmt.Fprintf(os.Stderr, "  Each input file must contain the following fields:\n")
		fmt.Fprintf(os.Stderr, "  --------------------------------------------------\n")
		fmt.Fprintf(os.Stderr, "  name: \"Query Name\"\n")
		fmt.Fprintf(os.Stderr, "  description: \"What this query does\"\n")
		fmt.Fprintf(os.Stderr, "  category: \"Category Name\" (Optional)\n")
		fmt.Fprintf(os.Stderr, "  query: |-\n")
		fmt.Fprintf(os.Stderr, "    MATCH (n) RETURN n\n")
		fmt.Fprintf(os.Stderr, "  --------------------------------------------------\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  Generate from directory:\n")
		fmt.Fprintf(os.Stderr, "    gen.exe -in ./my_queries -out ./library.go\n")
		fmt.Fprintf(os.Stderr, "  Generate from single file:\n")
		fmt.Fprintf(os.Stderr, "    gen.exe -in ./custom.yml -out ./library.go\n")
	}

	flag.Parse()

	if help {
		flag.Usage()
		os.Exit(0)
	}

	queries := make(map[string]QueryFile)

	// Check input info
	info, err := os.Stat(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error accessing input path: %v\n", err)
		os.Exit(1)
	}

	var files []string

	if info.IsDir() {
		entries, err := os.ReadDir(inputPath)
		if err != nil {
			panic(err)
		}
		for _, e := range entries {
			if !e.IsDir() && (strings.HasSuffix(e.Name(), ".yml") || strings.HasSuffix(e.Name(), ".yaml")) {
				files = append(files, filepath.Join(inputPath, e.Name()))
			}
		}
	} else {
		files = append(files, inputPath)
	}

	fmt.Printf("Processing %d files from %s...\n", len(files), inputPath)

	for _, path := range files {
		content, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("Skipping %s: %v\n", path, err)
			continue
		}

		var q QueryFile
		if err := yaml.Unmarshal(content, &q); err != nil {
			fmt.Printf("Failed to parse %s: %v\n", path, err)
			continue
		}

		// Normalize Key
		key := strings.ToLower(q.Name)
		key = strings.ReplaceAll(key, " ", "-")
		key = strings.ReplaceAll(key, "(", "")
		key = strings.ReplaceAll(key, ")", "")

		// Escape backticks for Go raw string literal
		q.Query = strings.ReplaceAll(q.Query, "`", "` + \"`\" + `")

		// Escape double quotes in Name and Description
		q.Name = strings.ReplaceAll(q.Name, "\"", "\\\"")
		q.Description = strings.ReplaceAll(q.Description, "\"", "\\\"")
		q.Category = strings.ReplaceAll(q.Category, "\"", "\\\"")

		queries[key] = q
	}

	// Ensure directory exists for output
	outDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		panic(err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	if err := packageTemplate.Execute(f, queries); err != nil {
		panic(err)
	}

	fmt.Printf("Successfully generated %d queries to %s\n", len(queries), outputPath)
}
