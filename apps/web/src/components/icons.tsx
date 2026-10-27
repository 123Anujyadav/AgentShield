import type { ReactNode } from "react";

interface IconProps { className?: string }

function Base({ className, children }: IconProps & { children: ReactNode }) {
  return (
    <svg className={className ?? "h-5 w-5"} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {children}
    </svg>
  );
}

export const ShieldIcon = (p: IconProps) => (<Base {...p}><path d="M12 3l7 2.5V11c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V5.5L12 3z" /><path d="M9 12l2 2 4-4" /></Base>);
export const GridIcon = (p: IconProps) => (<Base {...p}><rect x="4" y="4" width="7" height="7" rx="1" /><rect x="13" y="4" width="7" height="7" rx="1" /><rect x="4" y="13" width="7" height="7" rx="1" /><rect x="13" y="13" width="7" height="7" rx="1" /></Base>);
export const FlaskIcon = (p: IconProps) => (<Base {...p}><path d="M10 2v5.5L4.5 18a2 2 0 0 0 1.7 3h11.6a2 2 0 0 0 1.7-3L14 7.5V2" /><path d="M8.5 2h7M7 15h10" /></Base>);
export const SearchIcon = (p: IconProps) => (<Base {...p}><circle cx="11" cy="11" r="6" /><path d="M20 20l-3.8-3.8" /></Base>);
export const ScaleIcon = (p: IconProps) => (<Base {...p}><path d="M12 4v16M6 20h12M12 6l-4 6a3.5 3.5 0 0 0 8 0L12 6zM12 6l4 6" /><path d="M5 8l3-2 3 2M13 8l3-2 3 2" /></Base>);
export const CheckBadgeIcon = (p: IconProps) => (<Base {...p}><circle cx="12" cy="12" r="8" /><path d="M9 12.5l2 2 4-4.5" /></Base>);
export const ActivityIcon = (p: IconProps) => (<Base {...p}><path d="M3 12h4l2.5-6 4 12L16 12h5" /></Base>);
export const CpuIcon = (p: IconProps) => (<Base {...p}><rect x="6" y="6" width="12" height="12" rx="2" /><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3" /></Base>);
export const ToolIcon = (p: IconProps) => (<Base {...p}><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" /></Base>);
export const RefreshIcon = (p: IconProps) => (<Base {...p}><path d="M20 12a8 8 0 1 1-2.3-5.6M20 3v4h-4" /></Base>);
export const ChevronIcon = (p: IconProps) => (<Base {...p}><path d="M9 6l6 6-6 6" /></Base>);
export const AlertTriangleIcon = (p: IconProps) => (<Base {...p}><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></Base>);
export const AlertOctagonIcon = (p: IconProps) => (<Base {...p}><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></Base>);
export const CheckCircleIcon = (p: IconProps) => (<Base {...p}><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" /></Base>);
export const LockIcon = (p: IconProps) => (<Base {...p}><rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></Base>);
export const CopyIcon = (p: IconProps) => (<Base {...p}><rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></Base>);
export const CheckIcon = (p: IconProps) => (<Base {...p}><polyline points="20 6 9 17 4 12" /></Base>);
export const InfoIcon = (p: IconProps) => (<Base {...p}><circle cx="12" cy="12" r="10" /><line x1="12" y1="16" x2="12" y2="12" /><line x1="12" y1="8" x2="12.01" y2="8" /></Base>);
export const TerminalIcon = (p: IconProps) => (<Base {...p}><polyline points="4 17 10 11 4 5" /><line x1="12" y1="19" x2="20" y2="19" /></Base>);
