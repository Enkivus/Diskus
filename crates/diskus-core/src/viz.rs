//! Turning a [`ScanResult`] into something the treemap can actually render.
//!
//! A scan of a real machine produces millions of nodes. Handing all of them to
//! the frontend as JSON would be slow and pointless: a treemap 900 pixels wide
//! has room for perhaps a thousand visible rectangles, and anything below a few
//! pixels is indistinguishable from its neighbours.
//!
//! So this module produces a **bounded** tree. It walks the hierarchy
//! largest-first under a node budget and stops, marking where it stopped with
//! `truncated` so the UI can say "3 more folders not shown" rather than
//! silently presenting an incomplete picture as a complete one.
//!
//! Sharing the same JSON budget as the scan result is a non-goal. The treemap is
//! a navigation aid, not an audit log.

use crate::model::{Bytes, FileKind, ScanResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Total node budget for one rendered tree.
pub const DEFAULT_MAX_NODES: usize = 2500;

/// How deep the tree is expanded before `truncated` takes over.
pub const DEFAULT_MAX_DEPTH: u16 = 4;

/// Nodes below this size are never rendered.
pub const MIN_RENDERABLE: Bytes = 64 * 1024;

/// How the treemap tree should be shaped.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VizOptions {
    /// Maximum depth to expand.
    pub max_depth: u16,
    /// Maximum total nodes in the returned tree.
    pub max_nodes: usize,
    /// Subtrees smaller than this are pruned.
    pub min_size: Bytes,
}

impl Default for VizOptions {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            max_nodes: DEFAULT_MAX_NODES,
            min_size: MIN_RENDERABLE,
        }
    }
}

/// One rectangle's worth of the treemap.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VizNode {
    /// Full path, for tooltips and drill-down.
    pub path: PathBuf,
    /// Display name.
    pub name: String,
    /// What kind of entry this is.
    pub kind: FileKind,
    /// Bytes, recursive for directories.
    pub size: Bytes,
    /// Bytes actually allocated.
    pub on_disk: Bytes,
    /// Descendant files.
    pub file_count: u64,
    /// Descendant directories.
    pub dir_count: u64,
    /// Children, largest first.
    pub children: Vec<VizNode>,
    /// Whether children were omitted because of the budget or depth limit.
    pub truncated: bool,
    /// How many children were omitted, when `truncated`.
    pub omitted_children: u64,
}

impl VizNode {
    /// A synthetic root that holds the scan roots as its children.
    ///
    /// The UI needs a single root even when several volumes were scanned, and a
    /// synthetic node keeps the layout code from special-casing that case.
    #[must_use]
    pub fn synthetic_root(total: Bytes) -> Self {
        Self {
            path: PathBuf::from("/"),
            name: "Disk".to_string(),
            kind: FileKind::Dir,
            size: total,
            on_disk: total,
            file_count: 0,
            dir_count: 0,
            children: Vec::new(),
            truncated: false,
            omitted_children: 0,
        }
    }
}

/// Build a bounded tree from a scan result.
///
/// Deterministic: children are ordered by size descending, then by name, so the
/// same scan always produces the same layout.
#[must_use]
pub fn build_tree(result: &ScanResult, options: &VizOptions) -> VizNode {
    // The child index is the important one. Filtering the whole node list to find
    // a directory's children — inside a loop over up to `max_nodes` directories —
    // is O(nodes x budget). At the default ceilings that is billions of path
    // comparisons, and `get_results` is a synchronous command, so the window
    // would freeze outright on a large scan rather than merely run slowly.
    let index: HashMap<&std::path::Path, usize> = result
        .nodes
        .iter()
        .enumerate()
        .map(|(i, n)| (n.path.as_path(), i))
        .collect();

    let mut by_parent: HashMap<&std::path::Path, Vec<usize>> = HashMap::new();
    for (i, n) in result.nodes.iter().enumerate() {
        if let Some(parent) = n.parent.as_deref() {
            by_parent.entry(parent).or_default().push(i);
        }
    }

    let mut budget = options.max_nodes;
    let mut root = VizNode::synthetic_root(result.total_bytes);

    for scan_root in &result.roots {
        if budget == 0 {
            root.truncated = true;
            break;
        }
        match build_node(
            scan_root,
            &index,
            &by_parent,
            result,
            options,
            0,
            &mut budget,
        ) {
            Some(node) => root.children.push(node),
            None => {
                root.truncated = true;
                root.omitted_children += 1;
            }
        }
    }

    root.file_count = result.total_files;
    root.dir_count = result.total_dirs;
    root.on_disk = result.total_on_disk();

    // Roll truncation up to the root. A node only knows about *its own* omitted
    // children; the UI reads the root's flags for the "N folders not shown"
    // caption, so a partial view buried three levels down would otherwise be
    // presented as complete.
    propagate_truncation(&mut root);
    root
}

/// Copy `truncated` and `omitted_children` from descendants up to the root.
fn propagate_truncation(node: &mut VizNode) {
    let mut truncated = node.truncated;
    let mut omitted = node.omitted_children;
    for child in &mut node.children {
        propagate_truncation(child);
        truncated |= child.truncated;
        omitted += child.omitted_children;
    }
    node.truncated = truncated;
    node.omitted_children = omitted;
}

/// Build one node and its subtree, drawing from the shared node budget.
fn build_node<'a>(
    path: &std::path::Path,
    index: &HashMap<&std::path::Path, usize>,
    by_parent: &HashMap<&'a std::path::Path, Vec<usize>>,
    result: &'a ScanResult,
    options: &VizOptions,
    depth: u16,
    budget: &mut usize,
) -> Option<VizNode> {
    let &i = index.get(path)?;
    let node = &result.nodes[i];
    if !node.is_dir() || node.size < options.min_size {
        return None;
    }

    let mut children: Vec<&crate::model::ScanNode> = by_parent
        .get(path)
        .map(|ids| ids.iter().map(|&i| &result.nodes[i]).collect())
        .unwrap_or_default();
    children.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.name.cmp(&b.name)));

    let mut viz = VizNode {
        path: node.path.clone(),
        name: node.name.clone(),
        kind: node.kind,
        size: node.size,
        on_disk: node.on_disk,
        file_count: node.file_count,
        dir_count: node.dir_count,
        children: Vec::new(),
        truncated: false,
        omitted_children: 0,
    };

    for child in children {
        if *budget == 0 {
            viz.truncated = true;
            viz.omitted_children += 1;
            continue;
        }

        // A file child costs one node. A directory may cost many.
        if child.is_dir() {
            if depth + 1 >= options.max_depth {
                viz.truncated = true;
                viz.omitted_children += 1;
                continue;
            }
            *budget = budget.saturating_sub(1);
            if let Some(sub) = build_node(
                &child.path,
                index,
                by_parent,
                result,
                options,
                depth + 1,
                budget,
            ) {
                viz.children.push(sub);
            } else {
                viz.truncated = true;
                viz.omitted_children += 1;
            }
        } else {
            *budget = budget.saturating_sub(1);
            viz.children.push(VizNode {
                path: child.path.clone(),
                name: child.name.clone(),
                kind: child.kind,
                size: child.size,
                on_disk: child.on_disk,
                file_count: 1,
                dir_count: 0,
                children: Vec::new(),
                truncated: false,
                omitted_children: 0,
            });
        }
    }

    Some(viz)
}

/// The largest individual files in a scan, for the "top files" table.
///
/// Sorts indices rather than materialising a `TopFile` per node. Building the
/// full vector first would clone a `PathBuf` and a `String` for every file on the
/// machine — on a three-million-file scan that is hundreds of megabytes of
/// garbage produced to return 200 rows.
#[must_use]
pub fn top_files(result: &ScanResult, limit: usize) -> Vec<TopFile> {
    let mut indices: Vec<usize> = result
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| n.kind == FileKind::File)
        .map(|(i, _)| i)
        .collect();

    indices.sort_by(|&a, &b| {
        result.nodes[b]
            .size
            .cmp(&result.nodes[a].size)
            .then_with(|| result.nodes[a].path.cmp(&result.nodes[b].path))
    });
    indices.truncate(limit);

    indices
        .into_iter()
        .map(|i| {
            let n = &result.nodes[i];
            TopFile {
                path: n.path.clone(),
                name: n.name.clone(),
                size: n.size,
                on_disk: n.on_disk,
                modified: n.modified,
                extension: n.extension.clone().unwrap_or_default(),
            }
        })
        .collect()
}

/// A single row in the largest-files table.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopFile {
    /// Full path.
    pub path: PathBuf,
    /// File name.
    pub name: String,
    /// Apparent size in bytes.
    pub size: Bytes,
    /// Bytes actually allocated.
    pub on_disk: Bytes,
    /// Last modification time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<time::OffsetDateTime>,
    /// Lowercase extension, possibly empty.
    pub extension: String,
}

/// Count the nodes in a rendered tree. Used by tests and the "x folders shown"
/// caption.
#[must_use]
pub fn count_nodes(node: &VizNode) -> usize {
    1 + node.children.iter().map(count_nodes).sum::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScanConfig;
    use crate::scan::walker::walk;
    use crate::scan::{CancelToken, SilentObserver};

    fn scan(files: &[(&str, usize)]) -> (tempfile::TempDir, ScanResult) {
        let dir = tempfile::tempdir().expect("tempdir");
        for (rel, size) in files {
            let path = dir.path().join(rel);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(&path, vec![0_u8; *size]).expect("write");
        }
        let config = ScanConfig {
            roots: vec![dir.path().canonicalize().expect("canonical")],
            ..ScanConfig::default()
        };
        let result = walk(&config, &CancelToken::new(), &SilentObserver).expect("walk");
        (dir, result)
    }

    #[test]
    fn tree_root_totals_match_the_scan() {
        // Sizes are above `MIN_RENDERABLE`; anything smaller is pruned, which is
        // the point of the next test.
        let (_d, result) = scan(&[("a.bin", 200_000), ("sub/b.bin", 300_000)]);
        let tree = build_tree(&result, &VizOptions::default());
        assert_eq!(tree.size, result.total_bytes);
        assert_eq!(tree.file_count, result.total_files);
        assert_eq!(tree.children.len(), 1, "one scan root");
    }

    #[test]
    fn children_are_ordered_largest_first_and_deterministically() {
        let (_d, result) = scan(&[
            ("small.bin", 100),
            ("medium.bin", 10_000),
            ("big.bin", 1_000_000),
        ]);

        let first = build_tree(&result, &VizOptions::default());
        let second = build_tree(&result, &VizOptions::default());

        let names: Vec<&str> = first.children[0]
            .children
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(names, vec!["big.bin", "medium.bin", "small.bin"]);
        assert_eq!(
            count_nodes(&first),
            count_nodes(&second),
            "same scan, same layout, every time"
        );
    }

    #[test]
    fn the_node_budget_is_respected() {
        let files: Vec<(String, usize)> = (0..200)
            .map(|i| (format!("dir{i:03}/file.bin"), 100_000 + i))
            .collect();
        let refs: Vec<(&str, usize)> = files.iter().map(|(a, b)| (a.as_str(), *b)).collect();
        let (_d, result) = scan(&refs);

        let tree = build_tree(
            &result,
            &VizOptions {
                max_nodes: 50,
                ..VizOptions::default()
            },
        );

        // One synthetic root, one scan-root node, then whatever the budget buys.
        assert!(
            count_nodes(&tree) <= 2 + 50,
            "budget exceeded: {}",
            count_nodes(&tree)
        );
        assert!(tree.truncated, "the UI must be told the view is partial");
        assert!(tree.omitted_children > 0, "and how much was withheld");
    }

    #[test]
    fn depth_is_capped_and_reported() {
        let (_d, result) = scan(&[("a.bin", 1000), ("one/two/three/four/deep.bin", 5000)]);

        let tree = build_tree(
            &result,
            &VizOptions {
                max_depth: 2,
                ..VizOptions::default()
            },
        );

        assert!(tree.truncated);
        assert!(tree.omitted_children > 0, "the count of hidden branches");
        assert!(depth_of_deepest(&tree) <= 2, "depth limit honoured");
    }

    fn depth_of_deepest(node: &VizNode) -> u16 {
        node.children
            .iter()
            .map(|c| 1 + depth_of_deepest(c))
            .max()
            .unwrap_or(0)
    }

    #[test]
    fn tiny_subtrees_are_pruned() {
        let (_d, result) = scan(&[("big.bin", 5_000_000), ("dust/crumb.bin", 10)]);

        let tree = build_tree(&result, &VizOptions::default());
        let rendered: Vec<String> = tree.children[0]
            .children
            .iter()
            .map(|c| c.name.clone())
            .collect();
        assert!(
            !rendered.iter().any(|n| n == "dust"),
            "a 10-byte folder is not worth a rectangle: {rendered:?}"
        );
    }

    #[test]
    fn top_files_are_ranked_and_capped() {
        let (_d, result) = scan(&[
            ("a.bin", 100),
            ("b.bin", 900),
            ("c.bin", 500),
            ("d.bin", 700),
        ]);

        let top = top_files(&result, 2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].name, "b.bin");
        assert_eq!(top[1].name, "d.bin");
        assert!(top[0].size > top[1].size);
    }

    #[test]
    fn an_empty_scan_produces_an_empty_but_valid_tree() {
        let dir = tempfile::tempdir().expect("tempdir");
        let empty = dir.path().join("empty");
        std::fs::create_dir_all(&empty).expect("mkdir");

        let config = ScanConfig {
            roots: vec![empty.canonicalize().expect("canonical")],
            ..ScanConfig::default()
        };
        let result = walk(&config, &CancelToken::new(), &SilentObserver).expect("walk");

        let tree = build_tree(&result, &VizOptions::default());
        assert_eq!(tree.size, 0);
        assert!(tree.children.is_empty());
        assert_eq!(count_nodes(&tree), 1);
    }

    #[test]
    fn options_round_trip_as_camel_case() {
        let json = serde_json::to_string(&VizOptions::default()).expect("serialise");
        assert!(json.contains("maxDepth"), "{json}");
        assert!(json.contains("minSize"), "{json}");
    }
}
