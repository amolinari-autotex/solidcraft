//! Linked components retain the last inherited physical material and explicit body look
//! by imported body slot. Source-only property edits can then update the link while
//! differing local assignments survive. Older links have no baseline: existing assignments
//! are preserved and missing ones can be recovered on Update Links. The last release
//! refuses the newer design format instead of silently discarding these baselines.
