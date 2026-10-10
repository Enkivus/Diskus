/** Shared UI primitives.
 *
 * Small, unopinionated building blocks with no domain knowledge. Anything that
 * knows what a "finding" or a "detector" is lives in `components/domain`.
 */

import clsx from "clsx";
import {
  useEffect,
  useRef,
  useState,
  type CSSProperties,
  type ReactNode,
} from "react";

import { formatBytes } from "../../lib/format";

// ─── Button ───────────────────────────────────────────────────────────────

export interface ButtonProps {
  /** Visual weight. */
  variant?: "primary" | "secondary" | "ghost" | "danger";
  /** Button size. */
  size?: "sm" | "md" | "lg";
  /** Disabled state. */
  disabled?: boolean;
  /** Show a spinner and disable interaction. */
  loading?: boolean;
  /** Left-hand content. */
  icon?: ReactNode;
  /** Extra class names. */
  className?: string;
  /** Click handler. */
  onClick?: () => void;
  /** Accessible label, required when there is no text. */
  ariaLabel?: string;
  /** Tooltip text. */
  title?: string;
  /** Button content. */
  children?: ReactNode;
}

/** A button. */
export function Button({
  variant = "secondary",
  size = "md",
  disabled,
  loading,
  icon,
  className,
  onClick,
  ariaLabel,
  title,
  children,
}: ButtonProps) {
  return (
    <button
      type="button"
      className={clsx(
        "btn",
        `btn-${variant}`,
        size !== "md" && `btn-${size}`,
        !children && "btn-icon",
        className,
      )}
      disabled={disabled || loading}
      onClick={onClick}
      aria-label={ariaLabel}
      title={title}
      aria-busy={loading || undefined}
    >
      {loading ? <span className="spinner" /> : icon}
      {children}
    </button>
  );
}

// ─── Card ─────────────────────────────────────────────────────────────────

export interface CardProps {
  /** Panel heading. */
  title?: string;
  /** Content rendered to the right of the heading. */
  actions?: ReactNode;
  /** Extra class names. */
  className?: string;
  /** Padding override. */
  padded?: boolean;
  /** Card content. */
  children: ReactNode;
}

/** A titled panel. */
export function Card({ title, actions, className, padded = true, children }: CardProps) {
  return (
    <section className={clsx("card", className)}>
      {title && (
        <div className="row-between" style={{ marginBottom: 16 }}>
          <h2 className="card-title" style={{ marginBottom: 0 }}>
            {title}
          </h2>
          {actions}
        </div>
      )}
      <div style={padded ? undefined : { padding: 0 }}>{children}</div>
    </section>
  );
}

// ─── Badge ────────────────────────────────────────────────────────────────

export interface BadgeProps {
  /** Dot colour. */
  color?: string;
  /** Badge text. */
  children: ReactNode;
  /** Extra class names. */
  className?: string;
  /** Tooltip. */
  title?: string;
}

/** A small coloured pill. */
export function Badge({ color, children, className, title }: BadgeProps) {
  return (
    <span className={clsx("badge", className)} title={title}>
      {color && <span className="badge-dot" style={{ background: color }} />}
      {children}
    </span>
  );
}

// ─── Chip ─────────────────────────────────────────────────────────────────

export interface ChipProps {
  /** Whether the chip is selected. */
  pressed?: boolean;
  /** Leading colour dot. */
  color?: string;
  /** Click handler. */
  onClick?: () => void;
  /** Tooltip. */
  title?: string;
  /** Count badge. */
  count?: number;
  /** Chip content. */
  children: ReactNode;
}

/** A toggleable pill. */
export function Chip({ pressed, color, onClick, title, count, children }: ChipProps) {
  return (
    <button
      type="button"
      className="chip"
      aria-pressed={pressed}
      onClick={onClick}
      title={title}
    >
      {color && <span className="badge-dot" style={{ background: color }} />}
      {children}
      {count !== undefined && <span className="muted">{count}</span>}
    </button>
  );
}

// ─── Toggle ───────────────────────────────────────────────────────────────

export interface ToggleProps {
  /** Current state. */
  checked: boolean;
  /** Toggle handler. */
  onChange: (next: boolean) => void;
  /** Accessible label. */
  ariaLabel: string;
  /** Disabled state. */
  disabled?: boolean;
}

/** An on/off switch. */
export function Toggle({ checked, onChange, ariaLabel, disabled }: ToggleProps) {
  return (
    <button
      type="button"
      className="toggle"
      role="switch"
      aria-checked={checked}
      aria-label={ariaLabel}
      aria-pressed={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
    />
  );
}

/** A toggle with a label and description beside it. */
export function ToggleRow({
  label,
  help,
  checked,
  onChange,
  disabled,
}: {
  label: string;
  help?: string;
  checked: boolean;
  onChange: (next: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <div className="toggle-row">
      <div className="col" style={{ gap: 3 }}>
        <span style={{ fontSize: "var(--fs-base)", fontWeight: 550 }}>{label}</span>
        {help && <span className="field-help">{help}</span>}
      </div>
      <Toggle checked={checked} onChange={onChange} ariaLabel={label} disabled={disabled} />
    </div>
  );
}

// ─── Field ────────────────────────────────────────────────────────────────

/** A labelled form field. */
export function Field({
  label,
  help,
  children,
  className,
}: {
  label: string;
  help?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={clsx("field", className)}>
      <span className="field-label">{label}</span>
      {children}
      {help && <span className="field-help">{help}</span>}
    </div>
  );
}

// ─── Banner ───────────────────────────────────────────────────────────────

/** A highlighted message. */
export function Banner({
  tone = "info",
  icon,
  children,
  action,
}: {
  tone?: "info" | "warn" | "danger" | "privacy";
  icon?: ReactNode;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className={clsx("banner", `banner-${tone}`)} role={tone === "danger" ? "alert" : undefined}>
      {icon && <span style={{ flex: "none", lineHeight: 1.4 }}>{icon}</span>}
      <div style={{ flex: 1 }}>{children}</div>
      {action}
    </div>
  );
}

// ─── Empty state ──────────────────────────────────────────────────────────

/** A "nothing here" placeholder. */
export function EmptyState({
  icon,
  title,
  text,
  action,
}: {
  icon?: ReactNode;
  title: string;
  text?: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      {icon && <div className="empty-icon">{icon}</div>}
      <div className="empty-title">{title}</div>
      {text && <div className="empty-text">{text}</div>}
      {action}
    </div>
  );
}

// ─── Animated number ──────────────────────────────────────────────────────

/**
 * A number that counts up when its value changes.
 *
 * Animating the *number* rather than cross-fading two values keeps the eye on
 * one position, which is the whole point. `tabular-nums` in CSS keeps the width
 * stable while it runs, so nothing around it shifts.
 */
export function AnimatedNumber({
  value,
  format = (n: number) => Math.round(n).toLocaleString(),
  duration = 400,
}: {
  value: number;
  format?: (n: number) => string;
  duration?: number;
}) {
  const [display, setDisplay] = useState(value);
  const fromRef = useRef(value);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    const from = fromRef.current;
    if (from === value) return;

    // Respect the OS reduce-motion preference rather than animating anyway.
    const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    if (reduced || !Number.isFinite(from) || !Number.isFinite(value)) {
      fromRef.current = value;
      setDisplay(value);
      return;
    }

    const start = performance.now();
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      // easeOutCubic — fast start, gentle settle.
      const eased = 1 - (1 - t) ** 3;
      setDisplay(from + (value - from) * eased);
      if (t < 1) {
        rafRef.current = requestAnimationFrame(tick);
      } else {
        fromRef.current = value;
      }
    };
    rafRef.current = requestAnimationFrame(tick);

    return () => {
      if (rafRef.current !== null) cancelAnimationFrame(rafRef.current);
    };
  }, [value, duration]);

  return <span className="num">{format(display)}</span>;
}

/** {@link AnimatedNumber} preconfigured for byte counts. */
export function AnimatedBytes({ value, duration }: { value: number; duration?: number }) {
  return <AnimatedNumber value={value} format={formatBytes} duration={duration} />;
}

// ─── Meter ────────────────────────────────────────────────────────────────

/** A labelled confidence meter drawn as three segments. */
export function ConfidenceMeter({ value }: { value: number }) {
  const filled = value >= 0.8 ? 3 : value >= 0.55 ? 2 : value >= 0.3 ? 1 : 0;
  return (
    <span
      title={`${Math.round(value * 100)}% confidence`}
      style={{ display: "inline-flex", gap: 2 }}
      aria-label={`${Math.round(value * 100)} percent confidence`}
    >
      {[0, 1, 2].map((i) => (
        <span
          key={i}
          style={{
            width: 12,
            height: 3,
            borderRadius: 2,
            background:
              i < filled
                ? value >= 0.8
                  ? "var(--success)"
                  : value >= 0.55
                    ? "var(--warning)"
                    : "var(--danger)"
                : "var(--bg-overlay)",
            transition: "background var(--dur-base) var(--ease-out)",
          }}
        />
      ))}
    </span>
  );
}

// ─── Progress bar ─────────────────────────────────────────────────────────

/**
 * A determinate progress bar.
 *
 * `indeterminate` renders a shimmering band behind the fill for phases where
 * there is no meaningful percentage — duplicate hashing, for instance, where the
 * total is known only once the cheap size filter has run.
 */
export function ProgressBar({
  value,
  indeterminate,
  height = 5,
}: {
  value: number;
  indeterminate?: boolean;
  height?: number;
}) {
  return (
    <div
      className={clsx("progress-track", indeterminate && "progress-shimmer")}
      style={{ height }}
      role="progressbar"
      aria-valuenow={indeterminate ? undefined : Math.round(value * 100)}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div
        className="progress-fill"
        style={{ width: `${Math.max(0, Math.min(1, value)) * 100}%` }}
      />
    </div>
  );
}

// ─── Skeleton ─────────────────────────────────────────────────────────────

/** A loading placeholder. */
export function Skeleton({
  width = "100%",
  height = 14,
  style,
}: {
  width?: number | string;
  height?: number | string;
  style?: CSSProperties;
}) {
  return (
    <div
      className="skeleton"
      style={{ width, height, ...style }}
      aria-hidden="true"
    />
  );
}

// ─── Tooltip ──────────────────────────────────────────────────────────────

/**
 * A tooltip that follows the cursor.
 *
 * Deliberately not a title attribute: native tooltips cannot be styled, appear
 * after a delay the user did not ask for, and vanish the instant the pointer
 * moves. Paths need to be readable on hover without fighting the browser.
 */
export function Tooltip({
  content,
  children,
}: {
  content: ReactNode;
  children: ReactNode;
}) {
  const [visible, setVisible] = useState(false);
  const [position, setPosition] = useState({ x: 0, y: 0 });

  if (!content) return <>{children}</>;

  return (
    <span
      style={{ position: "relative", display: "inline-flex" }}
      onMouseEnter={(e) => {
        setPosition({ x: e.clientX, y: e.clientY });
        setVisible(true);
      }}
      onMouseMove={(e) => setPosition({ x: e.clientX, y: e.clientY })}
      onMouseLeave={() => setVisible(false)}
    >
      {children}
      {visible && (
        <span
          role="tooltip"
          style={{
            position: "fixed",
            left: Math.min(position.x + 14, window.innerWidth - 20),
            top: position.y + 16,
            transform: `translateX(-${Math.min(position.x + 14 > window.innerWidth - 260 ? 240 : 0)}px)`,
            background: "var(--bg-overlay)",
            border: "1px solid var(--border-strong)",
            borderRadius: "var(--radius-md)",
            boxShadow: "var(--shadow-md)",
            padding: "8px 11px",
            fontSize: "var(--fs-sm)",
            color: "var(--text-primary)",
            pointerEvents: "none",
            zIndex: 200,
            maxWidth: 380,
            animation: "fade-in 80ms var(--ease-out) both",
            lineHeight: 1.5,
          }}
        >
          {content}
        </span>
      )}
    </span>
  );
}

// ─── Icons ────────────────────────────────────────────────────────────────

/** Inline SVG icons. Kept tiny and stroke-based to match the type. */
export const Icon = {
  disk: (p: { size?: number }) => (
    <svg width={p.size ?? 18} height={p.size ?? 18} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <ellipse cx="12" cy="5" rx="9" ry="3" />
      <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" />
      <path d="M3 12c0 1.66 4 3 9 3s9-1.34 9-3" />
    </svg>
  ),
  scan: (p: { size?: number }) => (
    <svg width={p.size ?? 18} height={p.size ?? 18} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2" />
      <path d="M7 12h10" />
    </svg>
  ),
  chart: (p: { size?: number }) => (
    <svg width={p.size ?? 18} height={p.size ?? 18} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 3v18h18" />
      <rect x="7" y="11" width="3" height="6" rx="1" />
      <rect x="12" y="7" width="3" height="10" rx="1" />
      <rect x="17" y="13" width="3" height="4" rx="1" />
    </svg>
  ),
  list: (p: { size?: number }) => (
    <svg width={p.size ?? 18} height={p.size ?? 18} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" />
    </svg>
  ),
  export: (p: { size?: number }) => (
    <svg width={p.size ?? 18} height={p.size ?? 18} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <path d="M7 10l5 5 5-5M12 15V3" />
    </svg>
  ),
  settings: (p: { size?: number }) => (
    <svg width={p.size ?? 18} height={p.size ?? 18} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
    </svg>
  ),
  alert: (p: { size?: number }) => (
    <svg width={p.size ?? 18} height={p.size ?? 18} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <path d="M12 9v4M12 17h.01" />
    </svg>
  ),
  check: (p: { size?: number }) => (
    <svg width={p.size ?? 18} height={p.size ?? 18} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M20 6 9 17l-5-5" />
    </svg>
  ),
  shield: (p: { size?: number }) => (
    <svg width={p.size ?? 18} height={p.size ?? 18} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  ),
  folder: (p: { size?: number }) => (
    <svg width={p.size ?? 18} height={p.size ?? 18} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2z" />
    </svg>
  ),
  chevron: (p: { size?: number; dir?: "right" | "down" }) => (
    <svg
      width={p.size ?? 16}
      height={p.size ?? 16}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      style={{
        transform: p.dir === "down" ? "rotate(90deg)" : undefined,
        transition: "transform var(--dur-base) var(--ease-out)",
      }}
    >
      <path d="m9 18 6-6-6-6" />
    </svg>
  ),
  copy: (p: { size?: number }) => (
    <svg width={p.size ?? 16} height={p.size ?? 16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="9" y="9" width="13" height="13" rx="2" />
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </svg>
  ),
  close: (p: { size?: number }) => (
    <svg width={p.size ?? 16} height={p.size ?? 16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 6 6 18M6 6l12 12" />
    </svg>
  ),
  refresh: (p: { size?: number }) => (
    <svg width={p.size ?? 16} height={p.size ?? 16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 12a9 9 0 1 1-3-6.7L21 8" />
      <path d="M21 3v5h-5" />
    </svg>
  ),
  plus: (p: { size?: number }) => (
    <svg width={p.size ?? 16} height={p.size ?? 16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 5v14M5 12h14" />
    </svg>
  ),
};