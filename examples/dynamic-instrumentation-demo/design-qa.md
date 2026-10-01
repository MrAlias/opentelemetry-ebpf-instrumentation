# Dynamic instrumentation control plane design QA

## Comparison target

- Source visual truth:
  `/home/splunker/.codex/generated_images/01a0ee6e-d740-7221-bd30-f3bebdcbfb62/exec-dd6d3d32-70d9-4fc5-a6af-bf2b4a82a1e1.png`
- Browser implementation:
  `/tmp/obi-control-plane-composer.png`
- Full-view comparison: `/tmp/obi-control-plane-comparison.png`
- Focused composer comparison:
  `/tmp/obi-control-plane-focused-comparison.png`
- Rules workspace: `/tmp/obi-control-plane-rules.png`
- Responsive captures: `/tmp/obi-control-plane-tablet.png` and
  `/tmp/obi-control-plane-mobile.png`
- Source pixels: 1487 × 1058
- Implementation pixels: 1440 × 1046
- CSS viewport: 1440 × 1024 at device scale factor 1
- State: `coupon-checkout` selected with two available functions in a new rule
  draft

The full comparison places the source and implementation together at equal
display widths. The focused comparison preserves each source's natural pixel
density and crops the right edge to compare the rule composer directly.

## Full-view comparison

The implementation preserves the selected design's hierarchy:

1. Global OBI status and utilities remain in the application bar.
2. Service Inventory and Rules are conventional page-level workspaces.
3. The service table leads directly into the selected service's function table.
4. Function rows distinguish selected, instrumented, and available states and
   link instrumented functions to every owning rule.
5. Selecting functions opens a contextual rule composer directly under the
   global header.

The source visual uses illustrative data for eight services. The implementation
shows the three Go, Java, and Node.js services returned by the configured live
OBI selector. Language now comes from the symbol-discovery API rather than being
inferred from function names. Rule descriptions remain omitted because the API
does not accept them.

## Focused comparison

The composer matches the source's width, placement, dark surface, field order,
selected-function count, editable span names, advanced settings disclosure,
validation state, and primary action. It intentionally uses simple list rows
instead of draggable cards because rule member ordering has no API semantics.

No raster imagery is present in either the visual target or implementation.
The OBI wordmark remains text, and controls use native inputs rather than
substitute graphical assets.

## Required fidelity surfaces

- **Fonts and typography:** Both use a compact system sans-serif hierarchy and
  monospace function and span names. Sizes, weights, truncation, and line height
  preserve the target's developer-tool density.
- **Spacing and layout rhythm:** The 360-pixel composer and 14-pixel workspace
  gap match the target proportions. Twelve initial function rows keep the main
  workflow within the source's page height, with progressive loading for the
  remaining symbols.
- **Colors and visual tokens:** Navy surfaces, blue selection, mint success,
  amber ownership gaps, and subtle slate dividers map directly to the source.
- **Image quality and assets:** No image assets are required. Native controls
  remain sharp at all tested densities.
- **Copy and content:** Copy is oriented around services, functions, and rules.
  Trace analysis, Tempo controls, and Splunk controls are absent by design.

## Interaction verification

The browser test completed the primary lifecycle through the rendered UI:

1. Discovered one service and 6,798 exact functions.
2. Selected `main.checkout` and `main.main`.
3. Created `ui-qa-control-plane` through OBI's named rule endpoint.
4. Opened the rule in the Rules workspace.
5. Changed a span name and saved the replacement rule.
6. Deleted the temporary rule and returned OBI to the original five probes.

The original browser run exposed an ownership gap: OBI returned active probes
without their rule IDs, so the UI could not reconstruct the five owning rule
definitions. The implementation now exposes OBI's retained rule catalog through
`GET /v1/dynamic-instrumentation/rules`; the UI no longer infers ownership from
browser storage or labels active probes as unmanaged.

The corrected stack reports the five probes under `restored-demo-probes`, with
all five attachments in the `attached` state. Focused Go tests cover API and
configuration rule ownership, and the live demo smoke test covers the proxied
catalog endpoint.

The expanded runtime check discovered exactly three intended processes:
`coupon-checkout` (`go`, 6,798 symbols), `inventory-java` (`java`, 14 symbols),
and `inventory-node` (`nodejs`, 6 symbols). Temporary exact-symbol rules
attached to `demo.inventory.CatalogService.findProduct` and
`/app/catalog.cjs:exports.lookupStock`; Tempo returned repeated
`demo.dynamic.java` and `demo.dynamic.node` spans. Those validation rules were
then removed and the original five-function Go rule restored.

At 1024 and 390 pixels wide, the inventory, composer, and rules workspaces fit
the viewport without document-level horizontal overflow. Native tables retain
their own horizontal scrolling where necessary. Both responsive runs produced
no console errors or failed responses.

## Comparison history

| Iteration | Severity | Finding | Fix and post-fix evidence |
| --- | --- | --- | --- |
| Initial audit | P1 | The earlier UI began inside one service and centered trace observation instead of service and rule management. | Replaced it with service inventory, function ownership, contextual rule composition, and an editable Rules workspace. |
| First build | P2 | Rendering 120 functions made the inventory several screens taller than the source. | Reduced the initial page to 12 prioritized functions and added progressive loading; `/tmp/obi-control-plane-comparison.png` confirms comparable page density. |
| First build | P2 | The composer began beside the service table instead of behaving like the source's contextual drawer. | Moved it directly under the global header, reserved the right column across the page header, and extended it to the viewport bottom; the focused comparison confirms alignment. |

## Residual P3 differences

- The live demo has three matching services instead of the mock's eight
  illustrative services.
- Unsupported rule-description fields are omitted rather than fabricated.
- The source's decorative service icons and drag handles are omitted because
  neither conveys supported behavior in the current API.

No actionable P0, P1, or P2 findings remain.

## Final result

passed
