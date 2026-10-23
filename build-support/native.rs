use flate2::read::GzDecoder;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    error::Error,
    ffi::OsString,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

// Match the pinned upstream Makefile's PARSER_SRCS, TRANSFORM_SRCS,
// EXECUTOR_SRCS and RUNTIME_SRCS. Keeping this explicit prevents accidentally
// compiling an upstream CLI/test or an unlisted source from a previous build.
const GRAPHQLITE_SOURCES: &[&str] = &[
    "src/extension.c",
    "src/backend/parser/cypher_keywords.c",
    "src/backend/parser/cypher_scanner_api.c",
    "src/backend/parser/cypher_ast.c",
    "src/backend/parser/cypher_parser.c",
    "src/backend/transform/cypher_transform.c",
    "src/backend/transform/transform_match.c",
    "src/backend/transform/transform_create.c",
    "src/backend/transform/transform_set.c",
    "src/backend/transform/transform_delete.c",
    "src/backend/transform/transform_remove.c",
    "src/backend/transform/transform_foreach.c",
    "src/backend/transform/transform_load_csv.c",
    "src/backend/transform/transform_return.c",
    "src/backend/transform/transform_func_string.c",
    "src/backend/transform/transform_func_math.c",
    "src/backend/transform/transform_func_entity.c",
    "src/backend/transform/transform_func_path.c",
    "src/backend/transform/transform_func_list.c",
    "src/backend/transform/transform_func_temporal.c",
    "src/backend/transform/transform_func_geo.c",
    "src/backend/transform/transform_func_json.c",
    "src/backend/transform/transform_func_typeconv.c",
    "src/backend/transform/transform_func_graph.c",
    "src/backend/transform/transform_func_aggregate.c",
    "src/backend/transform/transform_func_dispatch.c",
    "src/backend/transform/transform_helpers.c",
    "src/backend/transform/transform_variables.c",
    "src/backend/transform/transform_expr_predicate.c",
    "src/backend/transform/transform_with.c",
    "src/backend/transform/transform_unwind.c",
    "src/backend/transform/transform_expr_ops.c",
    "src/backend/transform/transform_validate.c",
    "src/backend/transform/sql_builder.c",
    "src/backend/executor/cypher_schema.c",
    "src/backend/executor/cypher_executor.c",
    "src/backend/executor/executor_variable_map.c",
    "src/backend/executor/executor_foreach_ctx.c",
    "src/backend/executor/executor_result.c",
    "src/backend/executor/executor_helpers.c",
    "src/backend/executor/executor_delete.c",
    "src/backend/executor/executor_set.c",
    "src/backend/executor/executor_remove.c",
    "src/backend/executor/executor_create.c",
    "src/backend/executor/executor_foreach.c",
    "src/backend/executor/executor_merge.c",
    "src/backend/executor/executor_match.c",
    "src/backend/executor/query_dispatch.c",
    "src/backend/executor/executor_call_subquery.c",
    "src/backend/executor/executor_merge_pipeline.c",
    "src/backend/executor/executor_schema_objects.c",
    "src/backend/executor/executor_apoc.c",
    "src/backend/executor/executor_result_project.c",
    "src/backend/executor/agtype.c",
    "src/backend/executor/json_builder.c",
    "src/backend/executor/graph_algorithms.c",
    "src/backend/executor/graph_algo_pagerank.c",
    "src/backend/executor/graph_algo_community.c",
    "src/backend/executor/graph_algo_paths.c",
    "src/backend/executor/graph_algo_centrality.c",
    "src/backend/executor/graph_algo_components.c",
    "src/backend/executor/graph_algo_betweenness.c",
    "src/backend/executor/graph_algo_closeness.c",
    "src/backend/executor/graph_algo_louvain.c",
    "src/backend/executor/graph_algo_triangle.c",
    "src/backend/executor/graph_algo_astar.c",
    "src/backend/executor/graph_algo_traversal.c",
    "src/backend/executor/graph_algo_similarity.c",
    "src/backend/executor/graph_algo_knn.c",
    "src/backend/executor/graph_algo_eigenvector.c",
    "src/backend/executor/graph_algo_apsp.c",
    "src/backend/runtime/udf_helpers.c",
    "src/backend/runtime/apoc_helpers.c",
    "src/backend/runtime/udf_register.c",
    "src/backend/runtime/cypher_rows_vtab.c",
    "src/backend/runtime/gql_tz.c",
    "src/backend/runtime/gql_tzdata.c",
];

const PCRE2_SOURCES: &[&str] = &[
    "pcre2_auto_possess.c",
    "pcre2_chartables.c",
    "pcre2_chkdint.c",
    "pcre2_compile.c",
    "pcre2_compile_cgroup.c",
    "pcre2_compile_class.c",
    "pcre2_config.c",
    "pcre2_context.c",
    "pcre2_convert.c",
    "pcre2_dfa_match.c",
    "pcre2_error.c",
    "pcre2_extuni.c",
    "pcre2_find_bracket.c",
    "pcre2_jit_compile.c",
    "pcre2_maketables.c",
    "pcre2_match.c",
    "pcre2_match_data.c",
    "pcre2_match_next.c",
    "pcre2_newline.c",
    "pcre2_ord2utf.c",
    "pcre2_pattern_info.c",
    "pcre2_script_run.c",
    "pcre2_serialize.c",
    "pcre2_string_utils.c",
    "pcre2_study.c",
    "pcre2_substitute.c",
    "pcre2_substring.c",
    "pcre2_tables.c",
    "pcre2_ucd.c",
    "pcre2_valid_utf.c",
    "pcre2_xclass.c",
];

#[derive(Deserialize)]
pub struct SourceManifest {
    pub base_commit: String,
    pub source_archive_sha256: String,
    pub files: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct BuildInputs {
    files: BTreeMap<String, String>,
}

pub fn checksum(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

fn file_checksum(path: &Path) -> Result<String> {
    Ok(checksum(&fs::read(path)?))
}

fn safe_relative(name: &str) -> bool {
    !name.contains(['\\', ':', '\0'])
        && name
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

pub fn verify_inputs(root: &Path) -> Result<()> {
    let manifest: BuildInputs =
        serde_json::from_slice(&fs::read(root.join("vendor/build-inputs.json"))?)?;
    for (name, expected) in manifest.files {
        if !safe_relative(&name) {
            return Err(format!("invalid build input path: {name}").into());
        }
        println!("cargo:rerun-if-changed={name}");
        if file_checksum(&root.join(&name))? != expected {
            return Err(format!("build input checksum mismatch: {name}").into());
        }
    }
    Ok(())
}

pub fn extract_verified(
    archive: &Path,
    destination: &Path,
    inventory: &BTreeMap<String, String>,
) -> Result<()> {
    let mut archive = tar::Archive::new(GzDecoder::new(File::open(archive)?));
    let mut seen = BTreeSet::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path_bytes();
        let name = std::str::from_utf8(&path)?;
        let Some(relative) = name.strip_prefix("graphqlite/") else {
            return Err(format!("unexpected GraphQLite archive member: {name}").into());
        };
        if !entry.header().entry_type().is_file() || !safe_relative(relative) {
            return Err(format!("unexpected GraphQLite archive member: {name}").into());
        }
        let Some(expected) = inventory.get(relative) else {
            return Err(format!("uninventoried GraphQLite archive member: {name}").into());
        };
        if !seen.insert(relative.to_owned()) {
            return Err(format!("duplicate GraphQLite archive member: {name}").into());
        }
        let output = destination.join("graphqlite").join(relative);
        let expected = expected.clone();
        let mut data = Vec::new();
        entry.read_to_end(&mut data)?;
        if checksum(&data) != expected {
            return Err(format!(
                "GraphQLite archive file checksum mismatch: {}",
                output.display()
            )
            .into());
        }
        fs::create_dir_all(output.parent().unwrap())?;
        fs::write(output, data)?;
    }
    if seen.len() != inventory.len() {
        return Err("GraphQLite archive is missing inventoried files".into());
    }
    Ok(())
}

pub fn pinned_source(root: &Path, out: &Path) -> Result<(PathBuf, SourceManifest)> {
    let archive = root.join("vendor/graphqlite-source.tar.gz");
    let manifest: SourceManifest =
        serde_json::from_slice(&fs::read(root.join("vendor/graphqlite-source.json"))?)?;
    let digest = file_checksum(&archive)?;
    if digest != manifest.source_archive_sha256 {
        return Err("GraphQLite source archive checksum mismatch".into());
    }
    let destination = out.join(format!("backend-{}", &digest[..16]));
    // Cargo only reruns us when inputs change. Always start from a clean tree:
    // generated parser files and objects must not survive a source refresh.
    if destination.exists() {
        fs::remove_dir_all(&destination)?;
    }
    fs::create_dir_all(&destination)?;
    extract_verified(&archive, &destination, &manifest.files)?;
    Ok((destination.join("graphqlite"), manifest))
}

fn parser_tool(name: &str) -> Result<OsString> {
    if let Some(executable) = env::var_os(name.to_uppercase()) {
        let path = Path::new(&executable);
        // Resolve explicit relative paths before changing into the source tree.
        return Ok(if path.is_relative() && path.components().count() > 1 {
            env::current_dir()?.join(path).into_os_string()
        } else {
            executable
        });
    }
    // Apple's system Bison is too old for the grammar. These are host tools,
    // including when a macOS host is cross-compiling for another platform.
    if cfg!(target_os = "macos") {
        for prefix in ["/opt/homebrew/opt", "/usr/local/opt"] {
            let executable = Path::new(prefix).join(name).join("bin").join(name);
            if executable.is_file() {
                return Ok(executable.into_os_string());
            }
        }
    }
    Ok(name.into())
}

fn generate_parser(source: &Path) -> Result<()> {
    fs::create_dir_all(source.join("build/parser"))?;
    for (name, args) in [
        (
            "bison",
            vec![
                "-d",
                "-o",
                "build/parser/cypher_gram.tab.c",
                "src/backend/parser/cypher_gram.y",
            ],
        ),
        (
            "flex",
            vec![
                "-o",
                "build/parser/cypher_scanner.c",
                "--header=build/parser/cypher_flex.h",
                "src/backend/parser/cypher_scanner.l",
            ],
        ),
    ] {
        let executable = parser_tool(name)?;
        let status = Command::new(&executable)
            .args(args)
            .current_dir(source)
            .status()
            .map_err(|error| {
                format!(
                    "could not run {}: {error}; install {name} or set {} to its executable",
                    executable.to_string_lossy(),
                    name.to_uppercase()
                )
            })?;
        if !status.success() {
            return Err(
                format!("{name} failed with {status}; Beagle requires Bison 3 and Flex").into(),
            );
        }
    }
    Ok(())
}

pub fn build(
    root: &Path,
    out: &Path,
    sqlite_headers: &Path,
    windows_posix: Option<&Path>,
) -> Result<()> {
    for filename in ["sqlite3.h", "sqlite3ext.h"] {
        if !sqlite_headers.join(filename).is_file() {
            return Err(format!("missing bundled SQLite header: {filename}").into());
        }
    }
    let (source, manifest) = pinned_source(root, out)?;
    let pcre2_sources: Vec<String> = PCRE2_SOURCES
        .iter()
        .map(|name| format!("vendor/pcre2/{name}"))
        .collect();
    let expected: BTreeSet<&str> = GRAPHQLITE_SOURCES
        .iter()
        .copied()
        .chain(pcre2_sources.iter().map(String::as_str))
        .collect();
    let actual: BTreeSet<&str> = manifest
        .files
        .keys()
        .map(String::as_str)
        .filter(|name| {
            *name == "src/extension.c"
                || ((name.starts_with("src/backend/") || name.starts_with("vendor/pcre2/"))
                    && name.ends_with(".c"))
        })
        .collect();
    if expected != actual {
        return Err(
            "GraphQLite source inventory changed; update the Cargo native source lists".into(),
        );
    }
    generate_parser(&source)?;

    let mut native = cc::Build::new();
    native
        .pic(true)
        .warnings(false)
        .define("SQLITE_CORE", None)
        // Bundled SQLite must precede any MSYS2/system headers.
        .include(sqlite_headers)
        .include(source.join("src/include"))
        .include(source.join("build/parser"))
        .include(source.join("vendor/pcre2"))
        .files(GRAPHQLITE_SOURCES.iter().map(|name| source.join(name)))
        .file(source.join("build/parser/cypher_gram.tab.c"))
        .file(source.join("build/parser/cypher_scanner.c"));
    if let Some(prefix) = windows_posix {
        let include = prefix.join("include");
        if !include.join("regex.h").is_file() {
            return Err("missing Windows POSIX regex.h".into());
        }
        native.include(&include).flag("-include").flag(
            root.join(".github/build/windows_compat.h")
                .to_str()
                .ok_or("Windows compatibility header path must be UTF-8")?,
        );
        println!("cargo:rerun-if-changed={}", include.display());
        for library in ["systre", "tre", "intl", "iconv"] {
            let archive = prefix.join("lib").join(format!("lib{library}.a"));
            if !archive.is_file() {
                return Err(
                    format!("missing static Windows library: {}", archive.display()).into(),
                );
            }
            println!("cargo:rerun-if-changed={}", archive.display());
        }
    }
    let compiler = native.get_compiler();
    let compiler_command: Vec<String> = std::iter::once(compiler.path().as_os_str())
        .chain(compiler.args().iter().map(|arg| arg.as_os_str()))
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    native.compile("beagle_graphqlite");

    // PCRE2's defines apply only to its own compilation units. Emit its archive
    // after GraphQLite so static linkers resolve GraphQLite's PCRE2 references.
    cc::Build::new()
        .pic(true)
        .warnings(false)
        .define("PCRE2_CODE_UNIT_WIDTH", "8")
        .define("HAVE_CONFIG_H", None)
        .define("PCRE2_STATIC", None)
        .include(source.join("vendor/pcre2"))
        .files(pcre2_sources.iter().map(|name| source.join(name)))
        .compile("beagle_pcre2");

    let archive = out.join("libbeagle_graphqlite.a");
    let pcre2_archive = out.join("libbeagle_pcre2.a");
    let metadata = serde_json::json!({
        "archive": archive,
        "sha256": file_checksum(&archive)?,
        "pcre2_archive": pcre2_archive,
        "pcre2_sha256": file_checksum(&pcre2_archive)?,
        "source_commit": manifest.base_commit,
        "source_archive_sha256": manifest.source_archive_sha256,
        "sqlite_header_sha256": file_checksum(&sqlite_headers.join("sqlite3.h"))?,
        "compiler": compiler_command,
        "windows_posix_prefix": windows_posix,
    });
    fs::write(
        out.join("graphqlite-build.json"),
        format!("{}\n", serde_json::to_string_pretty(&metadata)?),
    )?;
    Ok(())
}
