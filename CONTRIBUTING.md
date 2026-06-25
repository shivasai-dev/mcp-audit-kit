# Contributing

Thanks for helping improve MCP Audit Kit.

## Good first contributions

- Add a fixture for a real MCP server shape.
- Improve a finding recommendation.
- Add a new rule with a focused test.
- Improve CLI output for CI users.
- Add SARIF output.

## Development

```bash
npm start
npm test
```

Rules live in `src/auditor.mjs`. Tests live in `tests/`.

## Rule design

Good rules should be:

- Easy to explain in one sentence.
- Backed by a realistic fixture.
- Conservative enough to avoid noisy reports.
- Paired with a concrete fix recommendation.
