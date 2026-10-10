/** The treemap.
 *
 * Disk sizes are the hero of this product, so the treemap is rendered as raw SVG
 * with full control over layout and motion rather than through a chart library.
 *
 * Three details that matter more than they look:
 *
 * * **Squarified layout.** `d3-hierarchy`'s squarified algorithm produces
 *   rectangles close to square, which is what makes a treemap legible. Slice-and-
 *   dice, the obvious alternative, gives long thin strips that are very hard to
 *   compare.
 * * **The colour is per top-level directory, not per rectangle.** A folder and
 *   its children share a hue so the eye reads them as one thing. Random colours
 *   per node turn the map into noise.
 * * **Labels are omitted on small rectangles.** A two-pixel rectangle with text in
 *   it is unreadable and costs legibility on its neighbours. Below ~90×30 units
 *   the label is dropped rather than shrunk.
 */

import { hierarchy, treemap } from "d3-hierarchy";
import { useMemo, useRef, useState } from "react";

import { formatBytes, formatCount, truncatePath, truncateName } from "../../lib/format";
import { colorForPath, type VizNode } from "../../lib/types";
import { AnimatedBytes, Tooltip } from "../primitives";

/** A rectangle in the rendered map. */
interface Rect {
  node: VizNode;
  x: number;
  y: number;
  width: number;
  height: number;
  color: string;
  depth: number;
}

export interface TreemapProps {
  /** Root of the bounded tree from the backend. */
  data: VizNode;
  /** Intrinsic width of the SVG user-space. */
  width?: number;
  /** Intrinsic height of the SVG user-space. */
  height?: number;
  /** Path currently drilled into. `null` shows the whole tree. */
  focusPath?: string | null;
  /** Called when a rectangle is clicked, to drill down. */
  onFocusChange?: (path: string | null) => void;
  /** Called when a rectangle is selected. */
  onSelect?: (node: VizNode) => void;
  /** Suppress the entrance animation, e.g. for a live-updating scan. */
  instant?: boolean;
}

/** Render the treemap. */
export function Treemap({
  data,
  width = 1000,
  height = 560,
  focusPath = null,
  onFocusChange,
  onSelect,
  instant = false,
}: TreemapProps) {
  const [hovered, setHovered] = useState<string | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);

  // The subtree the user has drilled into, or the whole tree.
  const root = useMemo(() => {
    if (!focusPath) return data;
    return findNode(data, focusPath) ?? data;
  }, [data, focusPath]);

  const rects = useMemo<Rect[]>(() => {
    if (root.size <= 0 || root.children.length === 0) return [];

    const build = hierarchy<VizNode>(root, (n) => n.children)
      .sum((n) => (n.children.length === 0 ? n.size : 0))
      .sort((a, b) => (b.value ?? 0) - (a.value ?? 0));

    const layout = treemap<VizNode>()
      .size([width, height])
      .paddingInner(1)
      .round(false)(build);

    return layout
      .descendants()
      .filter((d) => d.depth > 0 && d.x1 !== undefined && d.value)
      .map((d) => ({
        node: d.data,
        x: d.x0 ?? 0,
        y: d.y0 ?? 0,
        width: (d.x1 ?? 0) - (d.x0 ?? 0),
        height: (d.y1 ?? 0) - (d.y0 ?? 0),
        color: colorForTopLevel(root, d.data.path),
        depth: d.depth,
      }));
  }, [root, width, height]);

  if (rects.length === 0) {
    return (
      <div
        style={{
          height,
          display: "grid",
          placeItems: "center",
          color: "var(--text-tertiary)",
          fontSize: "var(--fs-base)",
          border: "1px dashed var(--border-default)",
          borderRadius: "var(--radius-md)",
        }}
      >
        Nothing large enough to map
      </div>
    );
  }

  return (
    <div style={{ position: "relative" }}>
      <svg
        ref={svgRef}
        viewBox={`0 0 ${width} ${height}`}
        style={{ width: "100%", height: "auto", display: "block" }}
        role="img"
        aria-label={`Treemap of ${root.name}, ${formatBytes(root.size)}`}
        onClick={(e) => {
          if (e.target === svgRef.current && onFocusChange) onFocusChange(null);
        }}
      >
        {rects.map((rect, i) => {
          const key = rect.node.path;
          const showLabel = rect.width > 92 && rect.height > 34;
          const isHovered = hovered === key;

          return (
            <g
              key={key}
              style={{
                cursor: rect.node.kind === "dir" ? "zoom-in" : "pointer",
                animation: instant
                  ? undefined
                  : `fade-in var(--dur-slow) var(--ease-out) ${Math.min(i * 6, 700)}ms both`,
                // `transform` and `opacity` only: the compositor handles these
                // without touching layout, so hovering stays smooth with hundreds
                // of rectangles on screen.
                transform: isHovered ? "scale(1.008)" : undefined,
                transformOrigin: `${rect.x + rect.width / 2}px ${rect.y + rect.height / 2}px`,
                transition: "transform var(--dur-fast) var(--ease-out)",
              }}
              onMouseEnter={() => setHovered(key)}
              onMouseLeave={() => setHovered((h) => (h === key ? null : h))}
              onClick={(e) => {
                e.stopPropagation();
                if (rect.node.kind === "dir") onFocusChange?.(rect.node.path);
                onSelect?.(rect.node);
              }}
            >
              <rect
                x={rect.x}
                y={rect.y}
                width={Math.max(0.5, rect.width)}
                height={Math.max(0.5, rect.height)}
                rx={2}
                fill={rect.color}
                fillOpacity={isHovered ? 0.95 : rect.node.kind === "dir" ? 0.82 : 0.68}
                stroke="rgba(0,0,0,0.35)"
                strokeWidth={0.5}
              />
              {showLabel && (
                <>
                  <text
                    x={rect.x + 8}
                    y={rect.y + 18}
                    fill="rgba(255,255,255,0.96)"
                    fontSize={12}
                    fontWeight={600}
                    pointerEvents="none"
                    style={{ userSelect: "none" }}
                  >
                    {truncateName(rect.node.name, Math.floor(rect.width / 7))}
                  </text>
                  {rect.height > 52 && (
                    <text
                      x={rect.x + 8}
                      y={rect.y + 36}
                      fill="rgba(255,255,255,0.72)"
                      fontSize={11}
                      fontFamily="var(--font-mono)"
                      pointerEvents="none"
                      style={{ userSelect: "none" }}
                    >
                      {formatBytes(rect.node.size)}
                    </text>
                  )}
                </>
              )}
            </g>
          );
        })}
      </svg>

      {/* A hover readout, because a tooltip on 300 rectangles would fight the
          pointer for the cursor. */}
      {hovered && <TreemapReadout node={rects.find((r) => r.node.path === hovered)?.node} />}
    </div>
  );
}

/** A floating summary of the hovered rectangle. */
function TreemapReadout({ node }: { node?: VizNode }) {
  if (!node) return null;
  return (
    <div
      style={{
        position: "absolute",
        right: 12,
        top: 12,
        background: "var(--bg-overlay)",
        border: "1px solid var(--border-strong)",
        borderRadius: "var(--radius-md)",
        boxShadow: "var(--shadow-md)",
        padding: "10px 13px",
        pointerEvents: "none",
        animation: "fade-in 100ms var(--ease-out) both",
        maxWidth: 340,
      }}
    >
      <div className="strong" style={{ fontSize: "var(--fs-base)" }}>
        {node.name}
      </div>
      <div className="mono" style={{ fontSize: "var(--fs-lg)", marginTop: 2 }}>
        <AnimatedBytes value={node.size} duration={200} />
      </div>
      <div className="muted" style={{ fontSize: "var(--fs-sm)", marginTop: 4 }}>
        {node.kind === "dir"
          ? `${formatCount(node.fileCount)} files · ${formatCount(node.dirCount)} folders`
          : truncatePath(node.path, 3)}
      </div>
      {node.onDisk > 0 && node.onDisk < node.size && (
        <div
          className="muted"
          style={{ fontSize: "var(--fs-xs)", marginTop: 4 }}
        >
          {formatBytes(node.onDisk)} allocated on disk
        </div>
      )}
    </div>
  );
}

/** Breadcrumb for the current drill-down level. */
export function TreemapBreadcrumb({
  data,
  focusPath,
  onFocusChange,
}: {
  data: VizNode;
  focusPath: string | null;
  onFocusChange: (path: string | null) => void;
}) {
  if (!focusPath) return null;

  const chain = pathTo(data, focusPath) ?? [data];
  return (
    <div className="row" style={{ gap: 6, fontSize: "var(--fs-sm)", flexWrap: "wrap" }}>
      <button className="btn btn-ghost btn-sm" onClick={() => onFocusChange(null)}>
        All locations
      </button>
      {chain.slice(1).map((node) => (
        <span key={node.path} className="row" style={{ gap: 6 }}>
          <span className="muted">/</span>
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => onFocusChange(node.path)}
          >
            {node.name}
          </button>
        </span>
      ))}
    </div>
  );
}

/**
 * Give a node the colour of its top-level ancestor.
 *
 * Depth is derived from the data's own tree rather than counted, because the
 * backend's `depth` field is advisory across roots at different nesting levels.
 */
function colorForTopLevel(root: VizNode, path: string): string {
  const top = firstChildPathOf(root, path);
  return colorForPath(top ?? path);
}

/** The deepest ancestor directly under `root` that contains `path`. */
function firstChildPathOf(root: VizNode, path: string): string | null {
  let current: VizNode = root;
  while (current.children.length > 0) {
    const next = current.children.find((c) =>
      path === c.path || path.startsWith(`${c.path}/`) || path.startsWith(`${c.path}\\`),
    );
    if (!next) return null;
    if (path === next.path || !next.children.length) return next.path;
    current = next;
  }
  return null;
}

/** Depth-first search for a node by path. */
export function findNode(root: VizNode, path: string): VizNode | null {
  if (root.path === path) return root;
  for (const child of root.children) {
    const found = findNode(child, path);
    if (found) return found;
  }
  return null;
}

/** The chain of nodes from `root` down to `path`. */
function pathTo(root: VizNode, path: string): VizNode[] | null {
  if (root.path === path) return [root];
  for (const child of root.children) {
    const chain = pathTo(child, path);
    if (chain) return [root, ...chain];
  }
  return null;
}

/** A legend explaining the colour encoding. */
export function TreemapLegend({ data }: { data: VizNode }) {
  const entries = data.children.slice(0, 12);
  if (entries.length === 0) return null;

  return (
    <div
      className="row"
      style={{ gap: 14, flexWrap: "wrap", marginTop: 12 }}
    >
      {entries.map((child) => (
        <Tooltip
          key={child.path}
          content={
            <span>
              {truncatePath(child.path, 5)}
              <br />
              {formatBytes(child.size)}
            </span>
          }
        >
          <span className="row" style={{ gap: 6 }}>
            <span
              style={{
                width: 9,
                height: 9,
                borderRadius: 2,
                background: colorForTopLevel(data, child.path),
                flex: "none",
              }}
            />
            <span style={{ fontSize: "var(--fs-sm)", color: "var(--text-secondary)" }}>
              {child.name}
            </span>
          </span>
        </Tooltip>
      ))}
    </div>
  );
}