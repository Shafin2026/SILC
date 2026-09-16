# SILC visual design and customization

The interface pairs a deep navy navigation rail with a light workspace and sapphire, violet, teal, amber and rose accents. Color organizes information; text labels carry its meaning.

## Design choices

| Element | Purpose |
| --- | --- |
| Light workspace and navy navigation | Separate investigation content from persistent navigation |
| Tinted metric cards | Make the first four numbers easy to scan |
| Rose Critical, amber High, blue Medium, green Low | Reinforce severity labels |
| Solid observed stages and dashed hypothesis cards | Distinguish records from possible next steps |
| Short Reasoning tabs | Keep explanations close to the finding |
| Hover and focus tooltips | Reveal exact chart values without filling the page with labels |
| Labeled chart controls | Provide a clear route from overview to investigation |
| Status labels and saved activity | Make analyst progress visible |
| Responsive layouts and native dialog | Support narrow screens and keyboard navigation |

## Install this complete version

This release changes both frontend and backend code. Use the complete extracted project folder from the ZIP.

1. Stop an older running copy with Control+C.
2. Extract the new ZIP into a fresh folder.
3. Open its START_HERE.html and run its start.sh.
4. If you previously configured a provider, copy your private configuration locally into the new project after reviewing it.
5. Open the new address printed in Terminal.

Do not mix only this stylesheet with an old backend; the Reasoning, context and log explorer features require the new API.

## Where to edit

| File | Edit here |
| --- | --- |
| frontend/styles.css | Colors, spacing, cards, charts, tab styles and responsive breakpoints |
| frontend/index.html | Logo, sidebar labels and app shell |
| frontend/app.js | Shared page content, queue, guide, uploads and provider controls |
| frontend/workspace.js | Timeline, donut, graph, Reasoning, evidence and saved assessments |
| frontend/favicon.svg | The S mark used in the browser tab |

The stylesheet includes the original base components followed by the current color and workspace components. Later rules intentionally override earlier defaults.

## A useful first frontend change

Personalize the top overview message or improve a label you found confusing.

1. Locate the relevant text in `silcOverview()` inside frontend/workspace.js.
2. Change the wording.
3. Refresh the browser.
4. Check a narrow window and keyboard navigation.
5. Record the reason in MY_CONTRIBUTIONS.md.

For a larger task, add a useful metric or a time filter in Log explorer. The events API already accepts time bounds, but the current log page does not expose them.

## Interaction details

- Timeline: hover/focus shows time, event count and findings first observed; click filters a ten-minute interval.
- Slider: updates the chart window while keeping the same slider control.
- Severity donut: segments and labeled legend buttons filter the queue.
- Detection bars: filter the alert type.
- Protocol bars: open Log explorer with that protocol.
- Connection nodes: show host context; activate to search its logs.
- Comparison rows: show observed count, threshold and earlier median where available.
- Evidence citations: open and highlight the relevant matching row.
- Case tabs: arrow keys, Home and End change the active tab.

## Visual checks

Test hover, focus, click, touch, browser zoom and small-window behavior in your browser. Use more than color alone to communicate status. Preserve visible focus and reduced-motion behavior when customizing.

Logic checks verify render strings and filter behavior. They do not replace a rendered browser inspection.
