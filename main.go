package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"deathhound/internal/library"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// Configuration Defaults
const defaultDbUri = "bolt://localhost:7687"
const defaultDbUser = "neo4j"
const defaultDbPass = "bloodhoundcommunityedition"

func main() {
	// 1. CLI Arguments
	modePtr := flag.String("mode", "", "Execution mode (e.g., 'kerberoast')")
	filePtr := flag.String("file", "", "Path to file containing Cypher query")
	uriPtr := flag.String("url", defaultDbUri, "Neo4j Bolt URI")
	userPtr := flag.String("u", defaultDbUser, "Neo4j User")
	passPtr := flag.String("p", defaultDbPass, "Neo4j Password")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "DeathHound - Headless BloodHound CLI\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  deathhound [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")

		// Custom flag printing for specific order: u, p, url, mode, query, file
		printFlag := func(f *flag.Flag) {
			s := fmt.Sprintf("  -%s", f.Name)
			name, usage := flag.UnquoteUsage(f)
			if len(name) > 0 {
				s += " " + name
			}
			// Boolean flags of one ascii char are shown nicely
			if len(s) <= 4 { // space, space, -, x
				s += "\t"
			} else {
				s += "\n    \t"
			}
			s += strings.ReplaceAll(usage, "\n", "\n    \t")
			if f.DefValue != "" {
				s += fmt.Sprintf(" (default %q)", f.DefValue)
			}
			fmt.Fprint(os.Stderr, s, "\n")
		}

		// We have to look them up manually to enforce order,
		// otherwise Verify/VisitAll is alphabetical.
		order := []string{"u", "p", "url", "mode", "file"}
		for _, name := range order {
			if f := flag.Lookup(name); f != nil {
				printFlag(f)
			}
		}
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  List all available queries:\n")
		fmt.Fprintf(os.Stderr, "    deathhound -mode list\n\n")
		fmt.Fprintf(os.Stderr, "  Run a specific attack primitive:\n")
		fmt.Fprintf(os.Stderr, "    deathhound -mode kerberoast\n")
		fmt.Fprintf(os.Stderr, "    deathhound -mode shortest-path\n\n")
		fmt.Fprintf(os.Stderr, "  Run from file (bypasses shell escaping issues):\n")
		fmt.Fprintf(os.Stderr, "    deathhound -file my_query.cypher\n\n")
		fmt.Fprintf(os.Stderr, "  Connect to a specific Neo4j instance:\n")
		fmt.Fprintf(os.Stderr, "    deathhound -u neo4j -p Secret -url bolt://192.168.1.10:7687 -mode domain-admins\n\n")
	}
	flag.Parse()

	if *modePtr == "" && *filePtr == "" {
		// Just fall through to STDIN logic if no flags provided
	}

	// 2. Connect to Neo4j
	ctx := context.Background()
	driver, err := neo4j.NewDriverWithContext(*uriPtr, neo4j.BasicAuth(*userPtr, *passPtr, ""))
	if err != nil {
		log.Fatalf("Connection failed: %v", err)
	}
	defer driver.Close(ctx)

	// 3. Determine Query
	var cypher string
	if *filePtr != "" {
		content, err := os.ReadFile(*filePtr)
		if err != nil {
			log.Fatalf("Failed to read file: %v", err)
		}
		cypher = string(content)
	} else if *modePtr != "" {
		if *modePtr == "list" {
			// Group by Category
			categories := make(map[string][]string)
			for k, v := range library.Queries {
				cat := v.Category
				if cat == "" {
					cat = "General"
				}
				categories[cat] = append(categories[cat], k)
			}

			// Sort Categories
			var sortedCats []string
			for k := range categories {
				sortedCats = append(sortedCats, k)
			}
			sort.Strings(sortedCats)

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

			for _, cat := range sortedCats {
				fmt.Fprintf(w, "\n[%s]\n", strings.ToUpper(cat))
				queries := categories[cat]
				sort.Strings(queries)
				for _, q := range queries {
					// Show name + description (truncated)
					desc := library.Queries[q].Description
					if len(desc) > 60 {
						desc = desc[:57] + "..."
					}
					fmt.Fprintf(w, "  %-40s\t%s\n", q, desc)
				}
			}
			w.Flush()
			return
		}

		var err error
		cypher, err = library.GetQuery(*modePtr)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
	} else {
		// 4. Try STDIN
		// Check if we have data on stdin (piped or interactive)
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			// Data is being piped
			content, err := io.ReadAll(os.Stdin)
			if err != nil {
				log.Fatalf("Failed to read stdin: %v", err)
			}
			cypher = string(content)
		} else {
			// Interactive mode? Or just error.
			// Let's allow interactive paste
			fmt.Fprintln(os.Stderr, "Reading query from Stdin... (Paste your query, then press Ctrl+Z or Ctrl+D and Enter)")
			content, err := io.ReadAll(os.Stdin)
			if err != nil {
				log.Fatalf("Failed to read stdin: %v", err)
			}
			cypher = string(content)

			if strings.TrimSpace(cypher) == "" {
				log.Fatal("No query provided via flags or stdin.")
			}
		}
	}

	// 4. Execute & Print
	resultJSON, err := runQuery(ctx, driver, cypher)
	if err != nil {
		log.Fatalf("Query failed: %v", err)
	}
	fmt.Println(resultJSON)
}

func runQuery(ctx context.Context, driver neo4j.DriverWithContext, cypher string) (string, error) {
	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		records, err := tx.Run(ctx, cypher, nil)
		if err != nil {
			return nil, err
		}

		var results []map[string]any
		for records.Next(ctx) {
			rec := records.Record()

			// MAP PROJECTION RULE:
			// If the query returns a single map, use it.
			// If it returns multiple columns, map keys to values.

			if len(rec.Values) == 1 {
				if val, ok := rec.Values[0].(map[string]any); ok {
					results = append(results, val)
					continue
				}
			}

			// Fallback: Create a map from all returned keys
			rowMap := make(map[string]any)
			for i, key := range rec.Keys {
				rowMap[key] = rec.Values[i]
			}
			results = append(results, rowMap)
		}
		return results, nil
	})

	if err != nil {
		return "", err
	}

	// Ensure we return an empty array [] not null if no results
	if res == nil {
		return "[]", nil
	}

	jsonBytes, _ := json.MarshalIndent(res, "", "  ")
	return string(jsonBytes), nil
}
