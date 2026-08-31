interface BadgeProps {
  className?: string;
}

/** Inline label for normative content. */
export function NormativeBadge({ className = "" }: BadgeProps) {
  return (
    <span
      className={`spec-badge normative ${className}`}
      aria-label="This content is normative"
      title="Normative — required for conformance"
    >
      Normative
    </span>
  );
}

/** Inline label for informative content (non-binding). */
export function InformativeBadge({ className = "" }: BadgeProps) {
  return (
    <span
      className={`spec-badge informative ${className}`}
      aria-label="This content is informative"
      title="Informative — context only, not required for conformance"
    >
      Informative
    </span>
  );
}
