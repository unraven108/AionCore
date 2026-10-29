-- Give the builtin Kiro agent its brand mark.
--
-- Migration 001 seeds Kiro (e044000d) with a NULL icon and the ACP Registry
-- publishes no logo for it, so the row fell back to a generic avatar while
-- every neighbouring registry agent had a mark. The official app icon now
-- lives at crates/aionui-assets/assets/logos/acp-registry/kiro.svg and is
-- served by the same /api/assets/logos route as the rest of the catalog.
--
-- Only fill an empty icon: a user-provided avatar (or a manual backfill) may
-- already be set, and this migration must never overwrite it.

UPDATE agent_metadata
SET icon = '/api/assets/logos/acp-registry/kiro.svg',
    updated_at = unixepoch('now','subsec')*1000
WHERE agent_source = 'builtin'
  AND agent_type = 'acp'
  AND backend = 'kiro'
  AND (icon IS NULL OR trim(icon) = '');
