# PE Tests - Isolated Testing Environment

This is a separate, isolated project to verify our understanding of PE file parsing without relying on the main codebase. We're testing the core concepts that will be used in the main NomadLoader project.

## Purpose

The purpose of this test project is to:

1. Verify core PE parsing concepts in a controlled environment
2. Test PE header parsing without Windows-specific dependencies
3. Create a reference implementation for the main project
4. Develop platform-agnostic components that can be tested on any OS

## What's Included

- **DOS Header Parsing**: Tests parsing and validating the DOS header (MZ signature)
- **e_lfanew Extraction**: Tests getting the offset to the PE header
- **C String Extraction**: Tests extracting null-terminated strings (for import names)

## How to Use

```bash
# Build the tests
cargo build

# Run the tests
cargo run
```

## Lessons Learned

1. The core PE parsing functionality doesn't need Windows-specific APIs
2. Headers and structures can be parsed in a platform-agnostic way
3. Conditional compilation should be used for Windows-specific runtime features
4. Dependency management is critical for cross-platform compatibility
5. Feature flags help isolate optional dependencies

## How to Apply These Lessons

When implementing the main NomadLoader project:

1. Keep all PE structure parsing in platform-agnostic code
2. Use `#[cfg(windows)]` only for runtime code that requires Windows APIs
3. Properly handle Windows-specific functions like K32EnumProcessModules
4. Use feature flags for optional dependencies
5. Provide clear error messages when features aren't available

## Next Steps

- Implement more comprehensive PE parsing tests
- Test section header parsing
- Test import directory parsing
- Test relocation parsing
- Create an in-memory PE mapping test

These tests will ensure the core parsing functionality works correctly before integrating it with Windows-specific features in the main project.