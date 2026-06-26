# Contributing

Secure is built around production invariants, not generic checklist volume.

Good contributions usually do one of these:

- add a new source-confirmed failure pattern;
- improve scanner signal without increasing false positives too much;
- improve benchmark coverage;
- make review output more measurable;
- add framework-specific guidance that maps back to a general invariant.

## Development

Run the benchmark fixture:

```bash
cd benchmark
npm test
```

Build the site:

```bash
cd site
npm install
npm run build
```

Validate Python scripts:

```bash
python -m py_compile skill/scripts/project_scraper.py skill/scripts/inventory_scan.py
```

## Review standards

Findings should include:

- severity;
- file or route evidence;
- production impact;
- invariant-restoring fix.

Avoid broad claims without source evidence.
