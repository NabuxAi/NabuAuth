#!/bin/sh
# Builds web/static/nabu.js: Nabu, the NabuOS logo's robot, as the sign-in page's interactive art.
#
# The art's source of truth is NabuCRM (resources/js/nabu-mascot: the rig, the pieces and the
# vendored anidoodle engine, Apache-2.0). This page needs only the sign-in piece, so it gets that
# one piece bundled on its own, with no NabuCRM runtime. Rebuild after the art changes there:
#
#   scripts/build-nabu-mascot.sh ../NabuCRM
set -eu
crm=${1:-../NabuCRM}
src="$crm/resources/js/nabu-mascot"
here=$(cd "$(dirname "$0")/.." && pwd)
entry="$src/.nabuauth-entry.ts"
trap 'rm -f "$entry"' EXIT
cat > "$entry" <<'TS'
import { define } from "./engine/interactive";
import { nabuForm } from "./nabuPieces";

// One pause button pauses Nabu on every visit; remembered on this device.
const KEY = "nabu.mascot.paused";
const paused = (): boolean => { try { return localStorage.getItem(KEY) === "1"; } catch { return false; } };
window.__ANI_PAUSED__ = paused;
define({ "nabu-form": nabuForm });

document.addEventListener("click", (e) => {
  const btn = (e.target as Element | null)?.closest?.(".ani-doodle-pause");
  if (!btn) return;
  setTimeout(() => {
    const own = (window.__anidoodle ?? []).find((c) => c.el.contains(btn));
    if (!own) return;
    try { localStorage.setItem(KEY, own.paused ? "1" : "0"); } catch { /* private mode */ }
  }, 0);
}, true);

// He hums while the form is sent.
document.addEventListener("submit", (e) => {
  if (!(e.target as HTMLFormElement | null)?.querySelector?.("[data-anidoodle]")) return;
  document.querySelectorAll<HTMLElement & { setState?: (s: string) => void }>('ani-doodle[piece="nabu-form"]').forEach((n) => n.setState?.("busy"));
}, true);
TS
"$crm/node_modules/.bin/esbuild" "$entry" --bundle --minify --format=iife --target=es2020 \
  --banner:js="/* Nabu sign-in art, built by scripts/build-nabu-mascot.sh from NabuCRM resources/js/nabu-mascot. Includes the anidoodle engine, Apache-2.0: see nabu.LICENSE.txt. */" \
  --outfile="$here/web/static/nabu.js"
cp "$src/LICENSE-anidoodle.txt" "$here/web/static/nabu.LICENSE.txt"
