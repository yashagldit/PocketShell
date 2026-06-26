//! Shared directory skip rules for project tree indexing and search.

pub const DEFAULT_MAX_DEPTH: usize = 6;
pub const SEARCH_MAX_DEPTH: usize = 10;

pub const SKIP_DIR_NAMES: &[&str] = &[
    "node_modules",
    ".git",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".next",
    ".expo",
    "vendor",
    "coverage",
    ".venv",
    "venv",
    ".turbo",
    ".cache",
    ".gradle",
    "pods",
    "deriveddata",
    ".idea",
    ".vs",
    ".pytest_cache",
    ".mypy_cache",
    "out",
    ".output",
    ".nuxt",
    ".svelte-kit",
    "bower_components",
    ".parcel-cache",
    ".terraform",
    ".serverless",
    ".yarn",
    "jspm_packages",
    ".pnpm",
    "carthage",
    ".build",
    "xcuserdata",
    ".svn",
    ".hg",
    ".nx",
    "buck-out",
    ".dart_tool",
    ".pub-cache",
    ".tox",
    ".eggs",
    "egg-info",
    ".sass-cache",
    ".angular",
    ".vercel",
    ".netlify",
];

pub fn should_skip_dir(name: &str, depth: usize, max_depth: usize) -> bool {
    if depth > max_depth {
        return true;
    }
    SKIP_DIR_NAMES
        .iter()
        .any(|skip| skip.eq_ignore_ascii_case(name))
}
