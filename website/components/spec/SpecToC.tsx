"use client";

import { useEffect, useState } from "react";
import type { Locale } from "@/lib/i18n";
import { t } from "@/lib/i18n";

export interface ToCEntry {
  num: string;
  title: string;
  id: string;
}

interface SpecToCProps {
  locale: Locale;
  entries: ToCEntry[];
}

export function SpecToC({ locale, entries }: SpecToCProps) {
  const [active, setActive] = useState<string | null>(null);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const observer = new IntersectionObserver(
      (items) => {
        const visible = items.filter((i) => i.isIntersecting);
        if (visible.length > 0) {
          const top = visible.reduce((a, b) =>
            a.boundingClientRect.top < b.boundingClientRect.top ? a : b,
          );
          setActive(top.target.id);
        }
      },
      { rootMargin: "-80px 0px -70% 0px", threshold: 0 },
    );
    entries.forEach((e) => {
      const el = document.getElementById(e.id);
      if (el) observer.observe(el);
    });
    return () => observer.disconnect();
  }, [entries]);

  return (
    <nav
      className="spec-toc"
      aria-label={t(locale, "spec.toc_aria")}
    >
      <p
        className="text-xs font-semibold uppercase tracking-wider text-stone mb-3"
        style={{ fontFamily: "var(--font-body)" }}
      >
        {t(locale, "spec.toc")}
      </p>
      <ol>
        {entries.map((e) => {
          const depth = e.num.split(".").length;
          return (
            <li key={e.id} style={{ marginLeft: `${(depth - 1) * 0.8}rem` }}>
              <a
                href={`#${e.id}`}
                className={active === e.id ? "active" : ""}
              >
                <span className="toc-section-num">§{e.num}</span>
                {e.title}
              </a>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
