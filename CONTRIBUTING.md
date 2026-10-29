# Contributing

1. `swift build` and `swift test` must pass locally (Command Line Tools are enough).
2. Keep the core free of third-party dependencies.
3. Any rule generation change needs a test — pf rejects malformed rules at load time, and a bad rule
   can silently cut network access.
4. New user-facing strings go to the CLI and the app, keep them in English.
5. Describe behaviour changes in `CHANGELOG.md`.
