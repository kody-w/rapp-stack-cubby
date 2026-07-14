"""Project-wide constants."""

from typing import Final

__version__: Final = "0.1.0rc11"
DISTRIBUTION_NAME: Final = "rapp-stack-cubby"
SOURCE_PACKAGE_NAME: Final = "rapp_stack_cubby"

SOURCE_CENSUS_SCHEMA: Final = "rapp-source-census/1.0"
CAPABILITY_MATRIX_SCHEMA: Final = "rapp-capability-matrix/1.0"
SYSTEM_GRAPH_SCHEMA: Final = "rapp-system-graph/1.0"
STACK_LOCK_SCHEMA: Final = "rapp-stack-lock/1.0"
PROVENANCE_SCHEMA: Final = "rapp-provenance/1.0"
CUBBY_SCHEMA: Final = "rapp-cubby/1.0"
AGENT_CATALOG_SCHEMA: Final = "rapp-local-agent-catalog/1.0"
IMPLEMENTATION_MATRIX_SCHEMA: Final = "rapp-implementation-matrix/1.0"
CONTROLLER_CATALOG_SCHEMA: Final = "rapp-controller-catalog/1.0"
CONTROLLER_LOADOUT_SCHEMA: Final = "rapp-controller-loadout/1.0"
CONTEXT_INDEX_SCHEMA: Final = "rapp-context-index/1.0"

EXPECTED_REPOSITORY_COUNT: Final = 307
EXPECTED_CAPABILITY_COUNT: Final = 113
EXPECTED_SELECTED_CAPABILITY_COUNT: Final = 61
EXPECTED_ACTUAL_AGENT_COUNT: Final = 12
EXPECTED_STREAMABLE_CONTROLLER_COUNT: Final = 1
EXPECTED_CONTEXT_SCHEMA_COUNT: Final = 57
MINIMUM_CAPABILITY_COUNT: Final = EXPECTED_CAPABILITY_COUNT

REPOSITORY_MARKERS: Final = ("SOURCE_CENSUS.json", "STACK_LOCK.json")
REQUIRED_TOP_LEVEL_FILES: Final = (
    ".editorconfig",
    ".gitattributes",
    ".gitignore",
    "AI_CONTEXT.md",
    "CAPABILITY_MATRIX.json",
    "CHANGELOG.md",
    "CONFORMANCE.md",
    "CONTRIBUTING.md",
    "CONTEXT_INDEX.json",
    "DEPENDENCY_LOCK.json",
    "GITHUB_ACTIONS_LOCK.json",
    "LICENSE",
    "Makefile",
    "NOTICE",
    "PROVENANCE.json",
    "RAPP_END_TO_END.md",
    "README.md",
    "RELEASE_CHECKLIST.md",
    "RELEASE_STATUS.json",
    "SBOM_INPUT.json",
    "SECURITY.md",
    "SOURCE_CENSUS.json",
    "STACK_LOCK.json",
    "SYSTEM_GRAPH.json",
    "STORE_INDEX.json",
    "VENDOR_MANIFEST.json",
    "VERSION",
    "birth.json",
    "pyproject.toml",
    "rapp-release-source-manifest.json",
    "rapp-super-rar.json",
    "rappid.json",
    "requirements-ci.lock",
    "requirements.lock",
)

CUBBY_ANATOMY: Final = (
    "agents",
    "organs",
    "senses",
    "rapplications",
    "neighborhoods",
    "eggs",
    "show-and-tell",
)
